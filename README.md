# WIM in Tamarin
This is the git repo accompanying the master's thesis "A Mechanized Model of the Web in Tamarin", soon to be available [here](https://www.research-collection.ethz.ch). In this thesis, we translate the [WIM](https://www.sec.uni-stuttgart.de/research/wim/) into a framework suitable for machine-assisted proving using [Tamarin](https://tamarin-prover.com/).

If you are looking to use our framework, take a look at the [user guide](docs/user_guide.md).

## Structure
The main part of our framework can be found in [wim.spthy](wim.spthy), some internals separated out in their [respective folder](internals).

Three examples of modelling protocols in our framework can be found in [the examples folder](examples). These are a login form, a CSRF attack on a session cookie, and a simplified OAuth 2.0. You can find proofs for these models in [the proofs folder](proofs).

A guide on how to use our framework is given in the [user guide](docs/user_guide.md).
