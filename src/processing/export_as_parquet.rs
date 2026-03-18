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

    for table in &tables {
        export_table(&conn, table, &args.output_dir)?;
    }

    eprintln!("export-parquet: done");
    Ok(())
}

// ---- per-table export ----

fn export_table(conn: &Connection, table: &str, output_dir: &PathBuf) -> Result<()> {
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
        return Ok(());
    }

    let row_count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM \"{}\"", table),
        [],
        |r| r.get(0),
    )?;

    eprint!("  {table}: {row_count} rows … ");

    // Build Arrow schema (all columns nullable)
    let schema = Arc::new(Schema::new(
        cols.iter()
            .map(|c| Field::new(&c.name, kind_to_arrow(&c.kind), true))
            .collect::<Vec<_>>(),
    ));

    let out_path = output_dir.join(format!("{table}.parquet"));
    let file =
        fs::File::create(&out_path).with_context(|| format!("creating {:?}", out_path))?;
    let props = WriterProperties::builder().build();
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props))
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
        writer.write(&batch).context("writing parquet batch")?;

        offset += fetched as i64;
        if fetched < BATCH_SIZE {
            break;
        }
    }

    writer.close().context("closing parquet writer")?;
    eprintln!("ok → {}", out_path.display());
    Ok(())
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
