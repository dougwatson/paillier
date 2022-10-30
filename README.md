# Paillier privacy preserving encryption
Example homomorphic encryption in pure 100% GO
(beta version - not constant time)

```
% ./paillier -generate
Private L=dbb3b2f5639fa00919427a52c38d06b0
Public  N=dbb3b2f5639fa00af3c279757d4adca1
```

```
% ./paillier -public dbb3b2f5639fa00af3c279757d4adca1 -private dbb3b2f5639fa00919427a52c38d06b0 -test
Encryption Result of 3:  adab5c854e1c1dfb57da619b0727ea463def4a9c61b979ee935d919d44610c65
Decryption Result of 3:  3
Encryption Result of 7:  637870f28544b014b9fe1b2c46e6afe25114b1061bc0336220f3c8a10ea781d8
Encryption Result of 3+7:  457321e96c17c0f86466b536e1bbf8878f8f875758741105c5d6095da752ab72
Result of 3+7 after decryption:  10
```

Based on code from https://github.com/Roasbeef/go-go-gadget-paillier
