This is a reproducible repo for https://github.com/privacy-scaling-explorations/maci/issues/460

# What's the issue?

- Decryption/Encryption by EcdhSharedKey works fine on JS using `circomlibjs` 0.1.4 
- However the decryption outputs are different when we decrypt on the circuit using `circomlib` 2.0.4
- You can observe the behavior in the test https://github.com/tomoima525/mimc-decrypt-encrypt-test/blob/main/circom/test/decrypt.test.ts 

# Side note
- this encryption/decryption logic is originally taken from [MACI](https://github.com/privacy-scaling-explorations/maci/blob/0a4f7cc0e355a191cc69f7b9fedb4440370a2abb/circuits/ts/__tests__/Decrypt.test.ts)
- MACI is using `0.5.1` of `circomlib` which used to include both circuits and JS code 

# How to test

```
yarn install
yarn test
```


