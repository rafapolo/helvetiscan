use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow::array::{
    Array, BinaryArray, BooleanArray, Float32Array, Float64Array, Int16Array, Int32Array,
    Int64Array, Int8Array, LargeBinaryArray, LargeStringArray, StringArray, UInt16Array,
    UInt32Array, UInt64Array, UInt8Array,
};
use arrow::datatypes::{DataType, Schema};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use rusqlite::{types::Value as SqlValue, Connection};

use crate::ImportParquetArgs;

// ---- entry point ----

pub(crate) fn cmd_import_parquet(args: ImportParquetArgs) -> Result<()> {
    let conn = Connection::open(&args.db)
        .with_context(|| format!("opening {:?}", args.db))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    let exclude: HashSet<String> = args.exclude.into_iter().collect();

    let conflict = match args.on_conflict.to_ascii_lowercase().as_str() {
        "ignore" => "IGNORE",
        "abort" => "ABORT",
        _ => "REPLACE",
    };

    let mut paths: Vec<PathBuf> = fs::read_dir(&args.input_dir)
        .with_context(|| format!("reading {:?}", args.input_dir))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "parquet"))
        .collect();

    if paths.is_empty() {
        eprintln!(
            "import-parquet: no .parquet files found in {}",
            args.input_dir.display()
        );
        return Ok(());
    }

    paths.sort();

    eprintln!(
        "import-parquet: {} file(s) in {} (conflict: {})",
        paths.len(),
        args.input_dir.display(),
        conflict.to_ascii_lowercase()
    );

    for path in &paths {
        let table = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };
        if exclude.contains(&table) {
            eprintln!("  {table}: excluded, skipping");
            continue;
        }
        import_file(&conn, path, &table, conflict)?;
    }

    eprintln!("import-parquet: done");
    Ok(())
}

// ---- per-file import ----

fn import_file(conn: &Connection, path: &PathBuf, table: &str, conflict: &str) -> Result<()> {
    let file = fs::File::open(path).with_context(|| format!("opening {:?}", path))?;

    let builder =
        ParquetRecordBatchReaderBuilder::try_new(file).context("building parquet reader")?;

    let schema: Arc<Schema> = builder.schema().clone();
    let reader = builder.build().context("building parquet record batch reader")?;

    ensure_table(conn, table, &schema)?;

    let col_names: Vec<String> = schema
        .fields()
        .iter()
        .map(|f| format!("\"{}\"", f.name()))
        .collect();
    let placeholders: Vec<String> = (1..=col_names.len()).map(|i| format!("?{i}")).collect();
    let sql = format!(
        "INSERT OR {conflict} INTO \"{table}\" ({}) VALUES ({})",
        col_names.join(", "),
        placeholders.join(", ")
    );

    let mut total_rows = 0usize;

    for batch_result in reader {
        let batch = batch_result.context("reading parquet batch")?;
        let n_rows = batch.num_rows();
        let n_cols = batch.num_columns();

        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(&sql)?;
            for row_idx in 0..n_rows {
                let params: Vec<SqlValue> = (0..n_cols)
                    .map(|ci| array_value(batch.column(ci).as_ref(), row_idx))
                    .collect();
                stmt.execute(rusqlite::params_from_iter(params.iter()))?;
            }
        }
        tx.commit()?;

        total_rows += n_rows;
        eprint!("\r  {table}: {total_rows} rows … ");
    }

    eprintln!("ok");
    Ok(())
}

// ---- table creation from parquet schema ----

fn ensure_table(conn: &Connection, table: &str, schema: &Schema) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |r| r.get::<_, i64>(0),
    )? > 0;

    if !exists {
        let col_defs: Vec<String> = schema
            .fields()
            .iter()
            .map(|f| format!("\"{}\" {}", f.name(), arrow_to_sqlite_affinity(f.data_type())))
            .collect();
        let ddl = format!(
            "CREATE TABLE IF NOT EXISTS \"{}\" ({})",
            table,
            col_defs.join(", ")
        );
        conn.execute_batch(&ddl)
            .with_context(|| format!("creating table {table}"))?;
        eprintln!("  {table}: table not found in DB, created from parquet schema");
    }

    Ok(())
}

fn arrow_to_sqlite_affinity(dt: &DataType) -> &'static str {
    match dt {
        DataType::Int8
        | DataType::Int16
        | DataType::Int32
        | DataType::Int64
        | DataType::UInt8
        | DataType::UInt16
        | DataType::UInt32
        | DataType::UInt64
        | DataType::Boolean => "INTEGER",
        DataType::Float16 | DataType::Float32 | DataType::Float64 => "REAL",
        DataType::Binary | DataType::LargeBinary | DataType::FixedSizeBinary(_) => "BLOB",
        _ => "TEXT",
    }
}

// ---- Arrow array → SQLite value ----

fn array_value(array: &dyn Array, idx: usize) -> SqlValue {
    if array.is_null(idx) {
        return SqlValue::Null;
    }

    match array.data_type() {
        DataType::Boolean => SqlValue::Integer(
            if array.as_any().downcast_ref::<BooleanArray>().unwrap().value(idx) {
                1
            } else {
                0
            },
        ),
        DataType::Int8 => SqlValue::Integer(
            array.as_any().downcast_ref::<Int8Array>().unwrap().value(idx) as i64,
        ),
        DataType::Int16 => SqlValue::Integer(
            array.as_any().downcast_ref::<Int16Array>().unwrap().value(idx) as i64,
        ),
        DataType::Int32 => SqlValue::Integer(
            array.as_any().downcast_ref::<Int32Array>().unwrap().value(idx) as i64,
        ),
        DataType::Int64 => {
            SqlValue::Integer(array.as_any().downcast_ref::<Int64Array>().unwrap().value(idx))
        }
        DataType::UInt8 => SqlValue::Integer(
            array.as_any().downcast_ref::<UInt8Array>().unwrap().value(idx) as i64,
        ),
        DataType::UInt16 => SqlValue::Integer(
            array.as_any().downcast_ref::<UInt16Array>().unwrap().value(idx) as i64,
        ),
        DataType::UInt32 => SqlValue::Integer(
            array.as_any().downcast_ref::<UInt32Array>().unwrap().value(idx) as i64,
        ),
        DataType::UInt64 => SqlValue::Integer(
            array.as_any().downcast_ref::<UInt64Array>().unwrap().value(idx) as i64,
        ),
        DataType::Float32 => SqlValue::Real(
            array.as_any().downcast_ref::<Float32Array>().unwrap().value(idx) as f64,
        ),
        DataType::Float64 => {
            SqlValue::Real(array.as_any().downcast_ref::<Float64Array>().unwrap().value(idx))
        }
        DataType::Utf8 => SqlValue::Text(
            array
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(idx)
                .to_owned(),
        ),
        DataType::LargeUtf8 => SqlValue::Text(
            array
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .unwrap()
                .value(idx)
                .to_owned(),
        ),
        DataType::Binary => SqlValue::Blob(
            array
                .as_any()
                .downcast_ref::<BinaryArray>()
                .unwrap()
                .value(idx)
                .to_owned(),
        ),
        DataType::LargeBinary => SqlValue::Blob(
            array
                .as_any()
                .downcast_ref::<LargeBinaryArray>()
                .unwrap()
                .value(idx)
                .to_owned(),
        ),
        other => SqlValue::Text(format!("<unsupported:{other}>")),
    }
}
