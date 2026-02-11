import { tableFromIPC } from "https://esm.sh/apache-arrow@21.1.0";

const fetchBytes = async (url) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ${url} (${res.status})`);
  return new Uint8Array(await res.arrayBuffer());
};

const fetchFirstAvailable = async (candidates, label) => {
  let lastErr = null;
  for (const candidate of candidates) {
    try {
      const bytes = await fetchBytes(candidate);
      return { bytes, path: candidate };
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(
    `Could not load ${label}. Tried: ${candidates.join(", ")}. Last error: ${lastErr?.message || lastErr}`,
  );
};

const resolveGraphInfo = (pointsBytes, linksBytes) => {
  const nodesTable = tableFromIPC(pointsBytes);
  const edgesTable = tableFromIPC(linksBytes);
  const nodeCols = new Set(nodesTable.schema.fields.map((f) => f.name));
  const edgeCols = new Set(edgesTable.schema.fields.map((f) => f.name));

  if (nodeCols.has("idx") && edgeCols.has("sourceidx") && edgeCols.has("targetidx")) {
    return {
      nodesCount: nodesTable.numRows,
      edgesCount: edgesTable.numRows,
      mappingConfig: {
        pointIndexBy: "idx",
        pointIdBy: "idx",
        linkSourceBy: "sourceidx",
        linkSourceIndexBy: "sourceidx",
        linkTargetBy: "targetidx",
        linkTargetIndexBy: "targetidx",
      },
    };
  }

  if (nodeCols.has("id") && edgeCols.has("source") && edgeCols.has("target")) {
    return {
      nodesCount: nodesTable.numRows,
      edgesCount: edgesTable.numRows,
      mappingConfig: {
        pointIdBy: "id",
        linkSourceBy: "source",
        linkTargetBy: "target",
      },
    };
  }

  throw new Error(
    `Unsupported Arrow schema. nodes: ${Array.from(nodeCols).join(", ")}; edges: ${Array.from(edgeCols).join(", ")}`,
  );
};

self.onmessage = async (event) => {
  const { nodesCandidates, edgesCandidates } = event.data || {};

  try {
    self.postMessage({ type: "progress", message: "worker: fetching arrow..." });

    const [nodesResult, edgesResult] = await Promise.all([
      fetchFirstAvailable(nodesCandidates, "nodes"),
      fetchFirstAvailable(edgesCandidates, "edges"),
    ]);

    self.postMessage({ type: "progress", message: "worker: parsing schema..." });

    const { mappingConfig, nodesCount, edgesCount } = resolveGraphInfo(
      nodesResult.bytes,
      edgesResult.bytes,
    );

    self.postMessage(
      {
        type: "loaded",
        nodesPath: nodesResult.path,
        edgesPath: edgesResult.path,
        nodesCount,
        edgesCount,
        mappingConfig,
        pointsBuffer: nodesResult.bytes.buffer,
        linksBuffer: edgesResult.bytes.buffer,
      },
      [nodesResult.bytes.buffer, edgesResult.bytes.buffer],
    );
  } catch (err) {
    self.postMessage({ type: "error", message: err?.message || String(err) });
  }
};
