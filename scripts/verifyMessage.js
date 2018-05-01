#!/usr/bin/env node

'use strict';

const Message = require('bitcore-message');
const fs = require('fs');
const readline = require('readline');
const program = require('commander');

program
  .description('Verify message signatures')
  .usage('<jsonl-file> <message-file>')
  .parse(process.argv);

if (program.args.length !== 2) {
  program.help();
}

const jsonlFile = program.args[0];
const messageFile = program.args[1];
const message = fs.readFileSync(messageFile, 'utf8');

let successCount = 0;
let failCount = 0;

var lineReader = readline.createInterface({
  input: fs.createReadStream(jsonlFile)
});

lineReader.on('line', (line) => {
  lineReader.pause();
  try {
    line = JSON.parse(line);
  } catch (e) {
    console.error(e);
    return lineReader.resume();
  }

  if (!line) {
    return lineReader.resume();
  }
  const verified = Message(message).verify(line.address, line.signature);
  if (verified) {
    successCount++;
  } else {
    failCount++;
    console.log(`Failed verification for address: ${line.address}`);
  }
  if ((successCount + failCount) % 1000 === 0) {
    console.log(`${new Date().toISOString()} : Success ${successCount}\tFail ${failCount}`);
  }
  lineReader.resume();
});

lineReader.on('close', () => {
  console.log(`Total Success: ${successCount}`);
  console.log(`Total Failures: ${failCount}`);
  console.log('Done!');
});
