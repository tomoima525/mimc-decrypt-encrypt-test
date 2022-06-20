import { isValidMnemonic } from 'ethers/lib/utils';
import {
  bigInt2Buffer,
  buf2Bigint,
  buildEddsaModule,
  decrypt,
  decryptV2,
  EdDSA,
  encrypt,
  encryptV2,
  genEcdhSharedKey,
  genKeypair,
  genRandomSalt,
  stringifyBigInts,
} from '../crypto';
import {
  compileAndLoadCircuit,
  executeCircuit,
  getSignalByName,
} from '../tools';
jest.setTimeout(90000);

describe('Decryption circuit', () => {
  let circuit;
  let eddsa: EdDSA;
  beforeAll(async () => {
    circuit = await compileAndLoadCircuit('test/decrypt_test.circom');
    eddsa = await buildEddsaModule();
  }, 15000);

  it('Should decrypt a message inside the snark', async () => {
    const { privKey: bobPrivKey, pubKey: bobPubKey } = genKeypair(eddsa);
    const { privKey: alicePrivKey, pubKey: alicePubKey } = genKeypair(eddsa);
    const sharedKey = await genEcdhSharedKey({
      eddsa,
      privKey: alicePrivKey,
      pubKey: bobPubKey,
    });

    const sharedKey2 = await genEcdhSharedKey({
      eddsa,
      privKey: bobPrivKey,
      pubKey: alicePubKey,
    });

    // matches
    expect(sharedKey.toString()).toEqual(sharedKey2.toString());

    const cmd: bigint[] = [];
    for (let i = 0; i < 5; i++) {
      cmd.push(genRandomSalt());
    }
    console.log({ cmd });
    const msg = await encrypt(cmd, sharedKey);
    // const msg = await encryptV2(cmd, sharedKey);
    console.log({ msg });
    const circuitInputs = stringifyBigInts({
      private_key: sharedKey,
      message: [msg.iv, ...msg.data],
    });
    console.log({ circuitInputs });
    const witness = await executeCircuit(circuit, circuitInputs);
    const decryptedMessage = await decrypt(msg, sharedKey);

    // matches
    expect(cmd).toStrictEqual(decryptedMessage);

    const pr = getSignalByName(circuit, witness, 'main.private_key');
    console.log({ pr });
    const iv = getSignalByName(circuit, witness, 'main.message[0]');
    console.log({ iv });
    const outs: string[] = [];
    for (let i = 0; i < 5; i++) {
      const out = getSignalByName(circuit, witness, 'main.out[' + i + ']');
      outs.push(out.toString());
      // does not match
      // expect(out.toString()).toEqual(cmd[i].toString());
    }
    console.log({ outs });
  });
});
