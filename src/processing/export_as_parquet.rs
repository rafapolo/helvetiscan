use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow::array::{ArrayRef, BinaryBuilder, Float64Builder, Int64Builder, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use rusqlite::Connection;

use crate::ExportParquetArgs;

// ---- column type inference ----

enum ColKind {
    Int,
    Float,
    Text,
    Blob,
}

fn infer_kind(declared_type: &str) -> ColKind {
    let u = declared_type.to_ascii_uppercase();
    if u.contains("INT") {
        ColKind::Int
    } else if u.contains("REAL")
        || u.contains("FLOAT")
        || u.contains("DOUBLE")
        || u.contains("NUMERIC")
        || u.contains("DECIMAL")
    {
        ColKind::Float
    } else if u.contains("BLOB") {
        ColKind::Blob
    } else {
        ColKind::Text
    }
}

fn kind_to_arrow(kind: &ColKind) -> DataType {
    match kind {
        ColKind::Int => DataType::Int64,
        ColKind::Float => DataType::Float64,
        ColKind::Text => DataType::Utf8,
        ColKind::Blob => DataType::Binary,
    }
}

struct ColInfo {
    name: String,
    kind: ColKind,
}

// ---- entry point ----

pub(crate) fn cmd_export_parquet(args: ExportParquetArgs) -> Result<()> {
    let conn = Connection::open(&args.db)
        .with_context(|| format!("opening {:?}", args.db))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating output dir {:?}", args.output_dir))?;

    let exclude: HashSet<String> = args.exclude.into_iter().collect();

    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
    )?;
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .filter_map(|r| r.ok())
        .filter(|name: &String| !exclude.contains(name))
        .collect();

    if tables.is_empty() {
        eprintln!("export-parquet: no tables to export (all excluded or db is empty)");
        return Ok(());
    }

    eprintln!(
        "export-parquet: exporting {} table(s) → {}",
        tables.len(),
        args.output_dir.display()
    );

    export_tables(&conn, &tables, &args.output_dir, None)?;

    eprintln!("export-parquet: done");
    Ok(())
}

/// One table's export result — used by callers (e.g. the `snapshot` command) that need to
/// record what was exported: row count for coverage bookkeeping, column list so a reader can
/// detect schema drift across runs without opening every file (task 26).
pub(crate) struct TableExport {
    pub(crate) table: String,
    pub(crate) row_count: i64,
    pub(crate) columns: Vec<String>,
}

/// Export a fixed, caller-chosen list of tables (or views) to `<output_dir>/<table>.parquet`.
/// `extra_col`, when set, appends a literal `(name, value)` text column to every row of every
/// table — used by `snapshot` to stamp an explicit `month` column into each file, so it
/// survives a file being copied out of its hive-partitioned `month=YYYY-MM/` directory.
pub(crate) fn export_tables(
    conn: &Connection,
    tables: &[String],
    output_dir: &PathBuf,
    extra_col: Option<(&str, &str)>,
) -> Result<Vec<TableExport>> {
    tables
        .iter()
        .map(|table| {
            let (row_count, columns) = export_table(conn, table, output_dir, extra_col)?;
            Ok(TableExport {
                table: table.clone(),
                row_count,
                columns,
            })
        })
        .collect()
}

// ---- per-table export ----

fn export_table(
    conn: &Connection,
    table: &str,
    output_dir: &PathBuf,
    extra_col: Option<(&str, &str)>,
) -> Result<(i64, Vec<String>)> {
    // Introspect columns via PRAGMA (cid, name, type, notnull, dflt_value, pk)
    let mut col_stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", table))?;
    let cols: Vec<ColInfo> = col_stmt
        .query_map([], |r| {
            let name: String = r.get(1)?;
            let decl_type: String = r.get::<_, Option<String>>(2)?.unwrap_or_default();
            Ok((name, decl_type))
        })?
        .filter_map(|r| r.ok())
        .map(|(name, decl_type)| ColInfo {
            name,
            kind: infer_kind(&decl_type),
        })
        .collect();

    if cols.is_empty() {
        eprintln!("  {table}: no columns, skipping");
        return Ok((0, Vec::new()));
    }

    let row_count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM \"{}\"", table),
        [],
        |r| r.get(0),
    )?;

    eprint!("  {table}: {row_count} rows … ");

    // Build Arrow schema (all columns nullable) — the base schema mirrors the SQL columns
    // exactly; `extra_col`, if set, is appended as one more nullable Utf8 field carrying a
    // constant value stamped onto every row (used for the snapshot's `month` column).
    let schema = Arc::new(Schema::new(
        cols.iter()
            .map(|c| Field::new(&c.name, kind_to_arrow(&c.kind), true))
            .collect::<Vec<_>>(),
    ));
    let full_schema = match extra_col {
        Some((name, _)) => {
            let mut fields: Vec<Field> = schema.fields().iter().map(|f| (**f).clone()).collect();
            fields.push(Field::new(name, DataType::Utf8, true));
            Arc::new(Schema::new(fields))
        }
        None => schema.clone(),
    };
    let column_names: Vec<String> = full_schema
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();

    let out_path = output_dir.join(format!("{table}.parquet"));
    let file =
        fs::File::create(&out_path).with_context(|| format!("creating {:?}", out_path))?;
    let props = WriterProperties::builder().build();
    let mut writer = ArrowWriter::try_new(file, full_schema.clone(), Some(props))
        .context("creating parquet writer")?;

    // Paginate to avoid loading the full table into memory
    const BATCH_SIZE: usize = 50_000;
    let col_exprs = cols
        .iter()
        .map(|c| format!("\"{}\"", c.name))
        .collect::<Vec<_>>()
        .join(", ");
    let paginated_sql = format!(
        "SELECT {col_exprs} FROM \"{}\" LIMIT {} OFFSET ?",
        table, BATCH_SIZE
    );
    let mut batch_stmt = conn.prepare(&paginated_sql)?;
    let n_cols = cols.len();
    let mut offset: i64 = 0;

    loop {
        let rows: Vec<Vec<rusqlite::types::Value>> = batch_stmt
            .query_map([offset], |row| {
                (0..n_cols)
                    .map(|i| row.get::<_, rusqlite::types::Value>(i))
                    .collect()
            })?
            .filter_map(|r| r.ok())
            .collect();

        if rows.is_empty() {
            break;
        }

        let fetched = rows.len();
        let batch = build_record_batch(&schema, &cols, &rows)?;
        let batch = match extra_col {
            Some((_, value)) => {
                let mut arrays = batch.columns().to_vec();
                let mut b = StringBuilder::with_capacity(fetched, fetched * value.len().max(1));
                for _ in 0..fetched {
                    b.append_value(value);
                }
                arrays.push(Arc::new(b.finish()));
                RecordBatch::try_new(full_schema.clone(), arrays)
                    .context("appending extra column to record batch")?
            }
            None => batch,
        };
        writer.write(&batch).context("writing parquet batch")?;

        offset += fetched as i64;
        if fetched < BATCH_SIZE {
            break;
        }
    }

    writer.close().context("closing parquet writer")?;
    eprintln!("ok → {}", out_path.display());
    Ok((row_count, column_names))
}

// ---- record batch builder ----

fn build_record_batch(
    schema: &Arc<Schema>,
    cols: &[ColInfo],
    rows: &[Vec<rusqlite::types::Value>],
) -> Result<RecordBatch> {
    use rusqlite::types::Value;

    let n = rows.len();

    let arrays: Vec<ArrayRef> = cols
        .iter()
        .enumerate()
        .map(|(ci, col)| -> Result<ArrayRef> {
            Ok(match col.kind {
                ColKind::Int => {
                    let mut b = Int64Builder::new();
                    for row in rows {
                        match &row[ci] {
                            Value::Integer(v) => b.append_value(*v),
                            Value::Real(v) => b.append_value(*v as i64),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
                ColKind::Float => {
                    let mut b = Float64Builder::new();
                    for row in rows {
                        match &row[ci] {
                            Value::Real(v) => b.append_value(*v),
                            Value::Integer(v) => b.append_value(*v as f64),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
                ColKind::Blob => {
                    let mut b = BinaryBuilder::new();
                    for row in rows {
                        match &row[ci] {
                            Value::Blob(v) => b.append_value(v),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
                ColKind::Text => {
                    let mut b = StringBuilder::with_capacity(n, n * 32);
                    for row in rows {
                        match &row[ci] {
                            Value::Text(v) => b.append_value(v),
                            Value::Integer(v) => b.append_value(v.to_string()),
                            Value::Real(v) => b.append_value(v.to_string()),
                            _ => b.append_null(),
                        }
                    }
                    Arc::new(b.finish())
                }
            })
        })
        .collect::<Result<_>>()?;

    RecordBatch::try_new(schema.clone(), arrays).context("building record batch")
}
