import fs from "fs";
import { parse } from "csv-parse";
import * as arrow from "apache-arrow";

function parseCsv(filePath, onRecord) {
  return new Promise((resolve, reject) => {
    const parser = parse({
      columns: true,
      relax_quotes: true,
      relax_column_count: true,
      skip_empty_lines: true,
      trim: true,
    });

    parser.on("readable", () => {
      let record;
      while ((record = parser.read()) !== null) {
        onRecord(record);
      }
    });
    parser.on("error", reject);
    parser.on("end", resolve);

    fs.createReadStream(filePath).pipe(parser);
  });
}

async function writeArrowFile(outPath, table) {
  const u8 = await arrow.tableToIPC(table, "file");
  fs.writeFileSync(outPath, Buffer.from(u8));
  return u8.length;
}

async function main() {
  const nodesCsvPath = "data/cosmo_nodes.csv";
  const edgesCsvPath = "data/cosmo_edges.csv";
  const nodesOut = "web/nodes.arrow";
  const edgesOut = "web/edges.arrow";

  console.log("Converting CSV to Arrow IPC (with idx/sourceidx/targetidx)...");
  console.log(`- ${nodesCsvPath}`);
  console.log(`- ${edgesCsvPath}`);

  if (!fs.existsSync(nodesCsvPath)) {
    throw new Error(`Missing ${nodesCsvPath}`);
  }
  if (!fs.existsSync(edgesCsvPath)) {
    throw new Error(`Missing ${edgesCsvPath}`);
  }

  // Nodes
  const idToIdx = new Map();
  const node_id = [];
  const node_label = [];
  const node_type = [];
  const node_idx = [];

  let nodeCount = 0;
  await parseCsv(nodesCsvPath, (r) => {
    const id = String(r.id ?? "");
    const label = String(r.label ?? "");
    const type = String(r.type ?? "");
    const idx = nodeCount++;

    node_id.push(id);
    node_label.push(label);
    node_type.push(type);
    node_idx.push(idx);
    idToIdx.set(id, idx);
  });
  console.log(`✓ Parsed nodes: ${nodeCount.toLocaleString()}`);

  // Edges
  const edge_source = [];
  const edge_target = [];
  const edge_type = [];
  const edge_sourceidx = [];
  const edge_targetidx = [];

  let edgeCount = 0;
  let skipped = 0;
  await parseCsv(edgesCsvPath, (r) => {
    const source = String(r.source ?? "");
    const target = String(r.target ?? "");
    const type = String(r.type ?? "");

    const sidx = idToIdx.get(source);
    const tidx = idToIdx.get(target);
    if (sidx === undefined || tidx === undefined) {
      skipped++;
      return;
    }

    edge_source.push(source);
    edge_target.push(target);
    edge_type.push(type);
    edge_sourceidx.push(sidx);
    edge_targetidx.push(tidx);
    edgeCount++;
  });
  console.log(`✓ Parsed edges: ${edgeCount.toLocaleString()} (skipped: ${skipped.toLocaleString()})`);

  // Build Arrow tables
  console.log("Building Arrow tables...");
  const nodesTable = arrow.tableFromArrays({
    id: node_id,
    label: node_label,
    type: node_type,
    idx: Int32Array.from(node_idx),
  });

  const edgesTable = arrow.tableFromArrays({
    source: edge_source,
    target: edge_target,
    type: edge_type,
    sourceidx: Int32Array.from(edge_sourceidx),
    targetidx: Int32Array.from(edge_targetidx),
  });

  // Write Arrow IPC files
  console.log("Writing Arrow files...");
  const nodesBytes = await writeArrowFile(nodesOut, nodesTable);
  const edgesBytes = await writeArrowFile(edgesOut, edgesTable);

  console.log("✓ Arrow files written:");
  console.log(`- ${nodesOut} (${(nodesBytes / 1024 / 1024).toFixed(2)} MB)`);
  console.log(`- ${edgesOut} (${(edgesBytes / 1024 / 1024).toFixed(2)} MB)`);
}

main().catch((err) => {
  console.error("Error:", err?.stack || err);
  process.exit(1);
});
