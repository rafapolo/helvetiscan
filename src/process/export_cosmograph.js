#!/usr/bin/env bun
import fs from 'fs';
import { getDomain } from 'tldts';

function csvRow(fields){
  return fields.map(f=>{
    if(f==null) f='';
    const s = String(f);
    if(/[,"\n]/.test(s)) return '"'+s.replace(/"/g,'""')+'"';
    return s;
  }).join(',') + '\n';
}

function parseCSVLine(line){
  const out = [];
  let cur = '';
  let inQuotes = false;
  for(let i=0;i<line.length;i++){
    const ch = line[i];
    if(ch === '"'){
      if(inQuotes && line[i+1] === '"') { cur += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if(ch === ',' && !inQuotes) {
      out.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function registrableDomain(host, usePsl){
  if(!host) return host;
  host = host.trim().replace(/\.+$/,'');
  if(!host) return host;
  if(usePsl){
    try{
      const d = getDomain(host);
      if(d) return d;
    }catch(e){ /* fallthrough */ }
  }
  const parts = host.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

function usage(){
  console.error('Usage: bun export_cosmograph.js <input.csv> [out_prefix] [no-psl]');
  process.exit(1);
}

const argv = process.argv.slice(2);
if(argv.length < 1) usage();
const infile = argv[0];
const prefix = argv[1] || 'cosmo';
let usePsl = true;
if(argv[2] && ['no-psl','nopsl','no_psl'].includes(argv[2].toLowerCase())) usePsl = false;

let text;
try{ text = fs.readFileSync(infile, 'utf8'); }
catch(e){ console.error('error: cannot open', infile); process.exit(1); }

const lines = text.split(/\r?\n/);
let idx = 0;
let nodes = new Map();
let edgesCount = 0;
const edgesFile = `${prefix}_edges.csv`;
const nodesFile = `${prefix}_nodes.csv`;
const edgesStream = fs.openSync(edgesFile, 'w');
fs.writeSync(edgesStream, csvRow(['source','target','type']));

// header detection
if(lines.length > 0){
  const firstCols = parseCSVLine(lines[0]);
  if(firstCols[0] && firstCols[0].trim().toLowerCase() === 'dominio'){
    idx = 1; // skip header
  } else {
    idx = 0; // treat first line as data
  }
}

// helper to ensure node
function ensureNode(id, label, type){
  if(!nodes.has(id)) nodes.set(id, [label, type]);
}

for(let i=idx;i<lines.length;i++){
  const line = lines[i];
  if(!line) continue;
  const cols = parseCSVLine(line);
  if(cols.length === 0) continue;
  const domain = (cols[0] || '').trim();
  const nsRaw = (cols[1] || '').trim();
  if(!domain) continue;
  ensureNode(domain, domain, 'domain');
  if(nsRaw){
    const parent = registrableDomain(nsRaw, usePsl);
    ensureNode(parent, parent, 'nameserver');
    fs.writeSync(edgesStream, csvRow([domain, parent, 'uses_ns']));
    edgesCount++;
  } else {
    const missing = '(no-ns)';
    ensureNode(missing, missing, 'nameserver');
    fs.writeSync(edgesStream, csvRow([domain, missing, 'uses_ns']));
    edgesCount++;
  }
}
fs.closeSync(edgesStream);

// write nodes
let nodesStream;
try{ nodesStream = fs.openSync(nodesFile, 'w'); }
catch(e){ console.error('error: cannot write', nodesFile); process.exit(1); }
fs.writeSync(nodesStream, csvRow(['id','label','type']));
for(const [id, [label, type]] of nodes){
  fs.writeSync(nodesStream, csvRow([id, label, type]));
}
fs.closeSync(nodesStream);

console.log(`Wrote ${nodes.size} nodes to ${nodesFile}`);
console.log(`Wrote ${edgesCount} edges to ${edgesFile}`);
