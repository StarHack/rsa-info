# rsa-info

This terminal-based project focuses on the extraction of data from a PEM-encoded RSA key. Both public and private keys are supported.

## Public Keys

If a public key is passed to the program, we currently read the following:

- Public Key Modulus
- Public key Exponent

### Examples

```
./rsa-info public_key.pem

This is an RSA public key (128-bit).
Public Key Modulus: 212095382819726758246329361763877768289
Public Key Exponent: 65537
```

```
./rsa-info public_key.pem

This is an RSA public key (2048-bit).
Public Key Modulus: 21623763358661421123501221806401219755487229142803897209098406850633308112128109066293142165198388388664285575751732315979375356211770512717233146168379296561056773720716852902333307897801785402736377394814817800182165298049361210385560489748930015822549662666481951396513679240737762543094597047914817414116484167782433207237483653708343500837822677880792173530105977250952092098313459006362383593197811477946031298730438778262858804194071407060527050399176912165914163073731584560740198793738970615068856490575305844421139166120310266976833024620887062563555472947138516703272258761354256479730341762370273243456969
Public Key Exponent: 65537
```

## Private Keys

If a private key is passed to the program, we currently read the following:

- Private Key Modulus
- Private key Exponent
- Primes

### Examples

```
./rsa-info private_key.pem

This is an RSA private key (128-bit).
Private Key Modulus: 212095382819726758246329361763877768289
Private Key Exponent: 67392072445152967226371984706598769153
Primes: [15013951711806318569 14126552881673661881]
```

```
./rsa-info private_key.pem

This is an RSA private key (2048-bit).
Private Key Modulus: 21623763358661421123501221806401219755487229142803897209098406850633308112128109066293142165198388388664285575751732315979375356211770512717233146168379296561056773720716852902333307897801785402736377394814817800182165298049361210385560489748930015822549662666481951396513679240737762543094597047914817414116484167782433207237483653708343500837822677880792173530105977250952092098313459006362383593197811477946031298730438778262858804194071407060527050399176912165914163073731584560740198793738970615068856490575305844421139166120310266976833024620887062563555472947138516703272258761354256479730341762370273243456969
Private Key Exponent: 6941763542775495354034243337120638149986966353898579327436736221225783440973240866163257671446799415736269652688415646060852314255145029785584756126104826591819483075364479121903511983487980272032144346087079843417192970469513564937391201059367053769483228601249885948872412492880079743414669992387198736219090257232486997922871265928161872134365662643007202536498182454880468722962659925378729520708134272181389825249514299954508243862361489129399199884967451863141742418301815752039109922165337111722465677662360904632937359706385909718293175817556137208641104190714768457232769286727394682002382450187778013050241
Primes: [141465118847188955140005579622548796268372451195896518992926643656303850919438162078790019317082767690613913637805050580080734318332228076604924894499813183448560659250506148579327978950088108047130840300738137874698881732595667503436134864048168612851166050367261114583095760947770040274950293894471012788313 152855796078038679167919475555658345564836698441610314288991310489795629075477019503623204630812088935404790512215519777525596944155695307253302706012148521192710505728471399404221403269813240851506860552710840396489443422012172304435443701647270573038446097927499688614824831089823799862723630747944079555313]
```

## Building

```
go build
```

## Pre-Built Binaries

There's a Github action that automatically builds the latest commit. Simply click on the latest build in the Actions tab.