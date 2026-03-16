# Proofs
In this subfolder you find all the proofs for all three protocols we investigated

# General Notes
Executability and Attack proofs have the `Browser_State` and Cookies facts unsolved. These would be tedious, but possible to connect, while the attack/protocol execution is already well visible in the graph of the unsolved proof.

# OAuth
The OAuth proof might be too large for Tamarin to open in interactive mode. Should that be the case, we have provided two files which split the proof, `OAuth_proof_no_params.spthy` and `OAUth_proof_params_only.spthy`. 

Due to time constraints, the OAuth theory deviates slightly from the others, as in, the source lemmas for parameters and referer are not source, but regular lemmas, as we could not get Tamarin's precomputations to terminate with them as source lemmas. 