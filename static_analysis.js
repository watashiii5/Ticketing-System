const fs = require('fs');
const content = fs.readFileSync('src/server.js', 'utf8');
const lines = content.split('\n');

let issuesFound = 0;

console.log("--- Starting Static Analysis of server.js ---");

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  const lineNumber = i + 1;
  const trimmed = line.trim();

  // 1. Missing await on db calls
  if (trimmed.includes('db.prepare') && !trimmed.includes('await') && !trimmed.startsWith('//')) {
    if (trimmed.includes('.get(') || trimmed.includes('.all(') || trimmed.includes('.run(')) {
      console.log(`[Line ${lineNumber}] Missing await: ${trimmed}`);
      issuesFound++;
    }
  }

  // 2. Multi-line missing await (db.prepare(`...`))
  if (trimmed.includes('db.prepare(`') && !trimmed.includes('await') && !trimmed.startsWith('//')) {
    console.log(`[Line ${lineNumber}] Missing await on multi-line: ${trimmed}`);
    issuesFound++;
  }

  // 3. Unparenthesized await property access
  if (line.match(/await\s+[\w\.]+\((.*?)\)\.\w+(?!\()/)) {
    if (!line.includes('(await')) {
      console.log(`[Line ${lineNumber}] Unparenthesized await property access: ${trimmed}`);
      issuesFound++;
    }
  }

  // 4. SQLite specific functions
  const sqliteFuncs = ['julianday', 'datetime(', 'strftime', 'IFNULL(']; // Postgres uses COALESCE, but IFNULL might work if custom or might fail
  for (const func of sqliteFuncs) {
    if (line.includes(func) && !trimmed.startsWith('//')) {
      console.log(`[Line ${lineNumber}] Potential SQLite function '${func}': ${trimmed}`);
      issuesFound++;
    }
  }

  // 5. Array IN clause check (like IN (?))
  if (line.includes('IN (?)') && !trimmed.startsWith('//')) {
     console.log(`[Line ${lineNumber}] SQL IN clause with single placeholder (might fail for arrays): ${trimmed}`);
     issuesFound++;
  }
}

// 6. Check for non-async functions that contain await
let currentFunc = null;
let currentFuncLine = 0;
let isAsync = false;
let braceDepth = 0;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  
  // Detect function start
  const funcMatch = line.match(/(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)/);
  if (funcMatch && !line.includes('app.get') && !line.includes('app.post')) {
    isAsync = line.includes('async');
    currentFuncLine = i + 1;
    braceDepth = 0;
  }
  
  for (const ch of line) {
    if (ch === '{') braceDepth++;
    if (ch === '}') braceDepth--;
  }

  if (line.includes('await') && braceDepth > 0 && !isAsync && currentFuncLine > 0) {
     // This is inside a non-async function
     // Exclude app routes which we didn't track perfectly
     // console.log(`[Line ${i+1}] await inside non-async function (started at ${currentFuncLine})`);
  }

  if (braceDepth === 0) {
    currentFuncLine = 0;
  }
}

console.log(`--- Analysis Complete: Found ${issuesFound} potential issues ---`);
