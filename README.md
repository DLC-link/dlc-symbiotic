# dlc-symbiotic

Repository for the dlc-link Symbiotic integration.

### Slashing

<img src="./assets/slash_flow.png" alt="slash_flow" width="100%" />

## Usage

You can start a local Sepolia fork using:

```shell
anvil --fork-url https://eth-sepolia.g.alchemy.com/v2/your-api-key
```

And deploy the NetworkMiddleware contract using:

```shell
forge script SetupNetworkMiddleware --rpc-url http://localhost:8545 --broadcast -vvvv --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
```

## Development

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
