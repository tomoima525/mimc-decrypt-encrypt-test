import path from 'path';
const wasm_tester = require('circom_tester').wasm;
/*
 * @param circuitPath The subpath to the circuit file (e.g.
 *     test/batchProcessMessage_test.circom)
 */
export const compileAndLoadCircuit = async (circuitPath: string) => {
  const circuit = await wasm_tester(
    path.join(__dirname, `../circom/${circuitPath}`),
  );

  await circuit.loadSymbols();

  return circuit;
};

export const executeCircuit = async (circuit: any, inputs: any) => {
  const witness = await circuit.calculateWitness(inputs, true);
  await circuit.checkConstraints(witness);
  await circuit.loadSymbols();

  return witness;
};

export const getSignalByName = (circuit: any, witness: any, signal: string) => {
  return witness[circuit.symbols[signal].varIdx];
};
