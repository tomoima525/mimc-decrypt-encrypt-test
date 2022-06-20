pragma circom 2.0.4;
include "../node_modules/circomlib/circuits/mimc.circom";
// include "./mimc7_r.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";


template Decrypt(N) {
  // Where N is the length of the
  // decrypted message
  signal input message[N+1];
  // signal input message[N];
  signal input private_key;
  // signal input iv;
  signal output out[N];

  component hasher[N];


  for(var i=0; i<N; i++) {
    // hasher[i] = MiMC7_r(91);
    hasher[i] = MiMC7(91);
    hasher[i].x_in <== private_key;
    hasher[i].k <== message[0] + i;
    out[i] <== message[i+1] - hasher[i].out;
  }
}