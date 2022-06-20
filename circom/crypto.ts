import assert from 'assert';
import * as crypto from 'crypto';
import * as ethers from 'ethers';
import { buildBabyjub, buildMimc7, poseidon, buildEddsa } from 'circomlibjs';

const createBlakeHash = require('blake-hash');

const ff = require('ffjavascript');
const stringifyBigInts: (obj: object) => any = ff.utils.stringifyBigInts;

type PrivKey = bigint;
type PubKey = Uint8Array[];
type EcdhSharedKey = Uint8Array;
type Plaintext = bigint[];

interface Keypair {
  privKey: PrivKey;
  pubKey: PubKey;
}

interface Ciphertext {
  // The initialisation vector
  iv: bigint;

  // The encrypted data
  data: bigint[];
}

// An EdDSA signature.
interface Signature {
  R8: BigInt[];
  S: BigInt;
}

interface EdDSA {
  prv2pub: (prv: string) => Uint8Array;
  pruneBuffer: () => Uint8Array;
  signPoseidon: (privKey: PrivKey, msg: bigint[]) => Signature;
  verifyPoseidon: (
    msg: bigint[],
    signature: Signature,
    pubKey: PubKey,
  ) => boolean;
}

const SNARK_FIELD_SIZE = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

// A nothing-up-my-sleeve zero value
// Should be equal to 8370432830353022751713833565135785980866757267633941821328460903436894336785
const NOTHING_UP_MY_SLEEVE =
  BigInt(
    ethers.utils.solidityKeccak256(
      ['bytes'],
      [ethers.utils.toUtf8Bytes('Maci')],
    ),
  ) % SNARK_FIELD_SIZE;

/*
 * Convert a BigInt to a Buffer
 */
const bigInt2Buffer = (i: BigInt): Buffer => {
  let hexStr = i.toString(16);
  while (hexStr.length < 64) {
    hexStr = '0' + hexStr;
  }
  return Buffer.from(hexStr, 'hex');
};
// The pubkey is the first Pedersen base point from iden3's circomlib
// See https://github.com/iden3/circomlib/blob/d5ed1c3ce4ca137a6b3ca48bec4ac12c1b38957a/src/pedersen_printbases.js
const NOTHING_UP_MY_SLEEVE_PUBKEY: PubKey = [
  bigInt2Buffer(
    10457101036533406547632367118273992217979173478358440826365724437999023779287n,
  ),
  bigInt2Buffer(
    19824078218392094440610104313265183977899662750282163392862422243483260492317n,
  ),
];

/**
 * A TypedArray object describes an array-like view of an underlying binary data buffer.
 */
type TypedArray =
  | Int8Array
  | Uint8Array
  | Uint8ClampedArray
  | Int16Array
  | Uint16Array
  | Int32Array
  | Uint32Array
  | Float32Array
  | Float64Array
  | BigInt64Array
  | BigUint64Array;

/**
 * Convert TypedArray object(like data buffer) into bigint
 * @param buf
 * @returns bigint
 */
const buf2Bigint = (buf: ArrayBuffer | TypedArray | Buffer): bigint => {
  let bits = 8n;
  if (ArrayBuffer.isView(buf)) bits = BigInt(buf.BYTES_PER_ELEMENT * 8);
  else buf = new Uint8Array(buf);

  let ret = 0n;
  for (const i of (buf as TypedArray | Buffer).values()) {
    const bi = BigInt(i);
    ret = (ret << bits) + bi;
  }
  return ret;
};

const buildEddsaModule = async (): Promise<EdDSA> => {
  return buildEddsa();
};

// Hash up to 2 elements
const poseidonT3 = (inputs: BigInt[]) => {
  assert(inputs.length === 2);
  return poseidon(inputs);
};

const poseidonT6 = (inputs: BigInt[]) => {
  assert(inputs.length === 5);
  return poseidon(inputs);
};

const hash5 = (elements: Plaintext): BigInt => {
  const elementLength = elements.length;
  if (elements.length > 5) {
    throw new Error(
      `elements length should not greater than 5, got ${elements.length}`,
    );
  }
  const elementsPadded = elements.slice();
  if (elementLength < 5) {
    for (let i = elementLength; i < 5; i++) {
      elementsPadded.push(BigInt(0));
    }
  }
  return poseidonT6(elementsPadded);
};

/*
 * A convenience function for to use Poseidon to hash a Plaintext with
 * no more than 11 elements
 */
const hash11 = (elements: Plaintext): BigInt => {
  const elementLength = elements.length;
  if (elementLength > 11) {
    throw new TypeError(
      `elements length should not greater than 11, got ${elementLength}`,
    );
  }
  const elementsPadded = elements.slice();
  if (elementLength < 11) {
    for (let i = elementLength; i < 11; i++) {
      elementsPadded.push(BigInt(0));
    }
  }
  return poseidonT3([
    poseidonT3([
      poseidonT6(elementsPadded.slice(0, 5)),
      poseidonT6(elementsPadded.slice(5, 10)),
    ]),
    elementsPadded[10],
  ]);
};

/*
 * Hash a single BigInt with the Poseidon hash function
 */
const hashOne = (preImage: BigInt): BigInt => {
  return poseidonT3([preImage, BigInt(0)]);
};

/*
 * Hash two BigInts with the Poseidon hash function
 */
const hashLeftRight = (left: BigInt, right: BigInt): BigInt => {
  return poseidonT3([left, right]);
};

/*
 * Returns a BabyJub-compatible random value. We create it by first generating
 * a random value (initially 256 bits large) modulo the snark field size as
 * described in EIP197. This results in a key size of roughly 253 bits and no
 * more than 254 bits. To prevent modulo bias, we then use this efficient
 * algorithm:
 * http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/lib/libc/crypt/arc4random_uniform.c
 * @return A BabyJub-compatible random value.
 */
const genRandomBabyJubValue = (): bigint => {
  // Prevent modulo bias
  //const lim = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000')
  //const min = (lim - SNARK_FIELD_SIZE) % SNARK_FIELD_SIZE
  const min = BigInt(
    '6350874878119819312338956282401532410528162663560392320966563075034087161851',
  );

  let rand;
  while (true) {
    rand = BigInt('0x' + crypto.randomBytes(32).toString('hex'));

    if (rand >= min) {
      break;
    }
  }

  const privKey: PrivKey = rand % SNARK_FIELD_SIZE;
  assert(privKey < SNARK_FIELD_SIZE);

  return privKey;
};

/*
 * @return A BabyJub-compatible private key.
 */
const genPrivKey = (): PrivKey => {
  return genRandomBabyJubValue();
};

/*
 * @return A BabyJub-compatible salt.
 */
const genRandomSalt = (): PrivKey => {
  return genRandomBabyJubValue();
};

/*
 * An internal function which formats a random private key to be compatible
 * with the BabyJub curve. This is the format which should be passed into the
 * PublicKey and other circuits.
 */
const formatPrivKeyForBabyJub = (eddsa: any, privKey: PrivKey) => {
  const sBuff = eddsa.pruneBuffer(
    createBlakeHash('blake512')
      .update(Buffer.from(privKey.toString()))
      .digest()
      .slice(0, 32),
  );
  const s = ff.utils.leBuff2int(sBuff);
  return ff.Scalar.shr(s, 3);
};

/*
 * Losslessly reduces the size of the representation of a public key
 * @param pubKey The public key to pack
 * @return A packed public key
 */
const packPubKey = async (pubKey: PubKey): Promise<Buffer> => {
  const babyJub = await buildBabyjub();
  return babyJub.packPoint(pubKey);
};

/*
 * Restores the original PubKey from its packed representation
 * @param packed The value to unpack
 * @return The unpacked public key
 */
const unpackPubKey = async (packed: Buffer): Promise<PubKey> => {
  const babyJub = await buildBabyjub();
  return babyJub.unpackPoint(packed);
};

/*
 * @param privKey A private key generated using genPrivKey()
 * @return A public key associated with the private key in uint8Array format
 */
const genPubKey = (eddsa: any, privKey: PrivKey): Uint8Array[] => {
  assert(privKey < SNARK_FIELD_SIZE);
  return eddsa.prv2pub(privKey.toString());
};

const genKeypair = (eddsa: any): Keypair => {
  const privKey = genPrivKey();
  const pubKey = genPubKey(eddsa, privKey);

  const Keypair: Keypair = { privKey, pubKey };

  return Keypair;
};

/*
 * Generates an Elliptic-curve Diffie–Hellman shared key given a private key
 * and a public key.
 * @return The ECDH shared key.
 */
const genEcdhSharedKey = async ({
  eddsa,
  privKey,
  pubKey,
}: {
  eddsa: any;
  privKey: PrivKey;
  pubKey: PubKey;
}): Promise<EcdhSharedKey> => {
  const babyJub = await buildBabyjub();
  return babyJub.mulPointEscalar(
    pubKey,
    formatPrivKeyForBabyJub(eddsa, privKey),
  )[0];
};

export const mimc7cts = async () => {
  const mimc7 = await buildMimc7();
  const a = mimc7.cts.map(c => buf2Bigint(c));
  console.log({ a });
};
/*
 * Encrypts a plaintext using a given key.
 * @return The ciphertext.
 */
export const encryptV2 = async (
  plaintext: Plaintext,
  sharedKey: EcdhSharedKey,
): Promise<Ciphertext> => {
  const mimc7 = await buildMimc7();
  // Generate the IV
  const ivBuffer = mimc7.multiHash(plaintext, BigInt(0));
  const iv: bigint = buf2Bigint(ivBuffer);
  const bigintSharedKey = buf2Bigint(sharedKey);
  const ciphertext: Ciphertext = {
    iv,
    data: plaintext.map((e: bigint, index: number): bigint => {
      const b = mimc7.F.e(e);
      return buf2Bigint(
        mimc7.F.add(
          b,
          mimc7.hash(
            bigintSharedKey,
            mimc7.F.e(iv + BigInt(index)),
            // mimc7.F.add(mimc7.F.e(iv), mimc7.F.e(index)),
          ),
        ),
      );
    }),
  };

  // TODO: add asserts here
  return ciphertext;
};

const encrypt = async (
  plaintext: Plaintext,
  sharedKey: EcdhSharedKey,
): Promise<Ciphertext> => {
  const mimc7 = await buildMimc7();
  // Generate the IV
  const iv: bigint = buf2Bigint(mimc7.multiHash(plaintext, BigInt(0)));
  const bigintSharedKey = buf2Bigint(sharedKey);
  const ciphertext: Ciphertext = {
    iv,
    data: plaintext.map((e: bigint, index: number): bigint => {
      return e + buf2Bigint(mimc7.hash(bigintSharedKey, iv + BigInt(index)));
    }),
  };

  // TODO: add asserts here
  return ciphertext;
};

/*
 * Decrypts a ciphertext using a given key.
 * @return The plaintext.
 */
const decrypt = async (
  ciphertext: Ciphertext,
  sharedKey: EcdhSharedKey,
): Promise<Plaintext> => {
  const mimc7 = await buildMimc7();
  const bigintSharedKey = buf2Bigint(sharedKey);
  const plaintext: Plaintext = ciphertext.data.map(
    (e: bigint, i: number): bigint => {
      return (
        e - buf2Bigint(mimc7.hash(bigintSharedKey, ciphertext.iv + BigInt(i)))
      );
    },
  );
  return plaintext;
};

export const decryptV2 = async (
  ciphertext: Ciphertext,
  sharedKey: EcdhSharedKey,
): Promise<Plaintext> => {
  const mimc7 = await buildMimc7();

  const bigintSharedKey = buf2Bigint(sharedKey);
  const plaintext: Plaintext = ciphertext.data.map(
    (e: bigint, i: number): bigint => {
      const b = bigInt2Buffer(e);
      const h = buf2Bigint(
        mimc7.hash(bigintSharedKey, ciphertext.iv + BigInt(i)),
      );
      console.log(`index ${i}: ${h}`);
      return buf2Bigint(
        mimc7.F.sub(b, mimc7.hash(bigintSharedKey, ciphertext.iv + BigInt(i))),
      );
    },
  );

  return plaintext;
};

/*
 * Generates a signature given a private key and plaintext.
 * @return The signature.
 */
const sign = async (privKey: PrivKey, msg: BigInt): Promise<Signature> => {
  const eddsa = await buildEddsa();
  return eddsa.signPoseidon(bigInt2Buffer(privKey), msg);
};

/*
 * Checks whether the signature of the given plaintext was created using the
 * private key associated with the given public key.
 * @return True if the signature is valid, and false otherwise.
 */
const verifySignature = async (
  msg: BigInt,
  signature: Signature,
  pubKey: PubKey,
): Promise<boolean> => {
  const eddsa = await buildEddsa();
  return eddsa.verifyPoseidon(msg, signature, pubKey);
};

export {
  buildEddsaModule,
  buf2Bigint,
  genRandomSalt,
  genPrivKey,
  genPubKey,
  genKeypair,
  genEcdhSharedKey,
  encrypt,
  decrypt,
  sign,
  hashOne,
  hash5,
  hash11,
  hashLeftRight,
  verifySignature,
  Signature,
  PrivKey,
  PubKey,
  Keypair,
  EcdhSharedKey,
  EdDSA,
  Ciphertext,
  Plaintext,
  TypedArray,
  formatPrivKeyForBabyJub,
  NOTHING_UP_MY_SLEEVE,
  NOTHING_UP_MY_SLEEVE_PUBKEY,
  SNARK_FIELD_SIZE,
  bigInt2Buffer,
  packPubKey,
  unpackPubKey,
  stringifyBigInts,
};
