# Trust Model : Securing digital identity with advanced cryptographic algorithms 
![Orange banner](./media/top-banner.png)

## Purpose
This repository aims at documenting the security and privacy risks that could arise from the implementation of the high level requirements and specifications of the [European Digital Identity Wallet Architecture and Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/tree/main). It also aims to provide and describe solutions (based in part on [BBS# protocol description](https://github.com/user-attachments/files/19198669/The_BBS_Sharp_Protocol.pdf)) to limit or resolve these risks, and to present their implementation in the main use cases of the European Digital Identity Wallet.

## Structure
| Chapter | Description | Status |
|--|---|--|
|[Introduction](./Trust-model-Introduction.md)| Description of the aims, structure and context of the repository |[![Version 1.0](https://img.shields.io/badge/Version-1.0-ff0288)](https://github.com/Orange-OpenSource/BBS-SHARP-doc-eudi-wallet/releases/tag/1.0.0)|
|[Privacy on credential presentation](./Trust-model-privacy-on-attestation-presentation.md) | This chapter describes the risks and critical solutions for ensuring the Holder's privacy when sharing Verifiable Credentials (attestations).| [![Version 1.0](https://img.shields.io/badge/Version-1.0-ff0288)](https://github.com/Orange-OpenSource/BBS-SHARP-doc-eudi-wallet/releases/tag/1.0.0) |
|Privacy on credential issuance and presentation | This chapter outlines supplementary risks and solutions essential for ensuring the Holder's privacy during the issuance and presentation of Verifiable Credentials (attestations).| In progress |
|Other Important Features | This chapter explores supplementary mechanisms that can be implemented to enhance the overall security and privacy of the system, providing advanced features for a more robust digital identity framework. | In progress |

## Generate diagrams from plantuml code
1. Prerequisites : Install make and plantuml in your environment
2. Run the following command to generate the PDF version `make diagrams`
3. The generated files are located in the folder "media"

## Generate a PDF version of the documentation
1. Prerequisites : Install make, pandoc, miktex in your environment
2. Run the following command to generate the PDF version `make all`
3. The generated file is located in the folder

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on the process for submitting pull requests.

## Versioning
Please read [CHANGELOG.md](CHANGELOG.md) for documentation version history and description.

## Authors
The main contributor to this project is Orange SA. 
For the full list of participants, see the repository [contributors](https://github.com/Orange-OpenSource/BBS-SHARP-doc-eudi-wallet/graphs/contributors) list. 

## License
See the [LICENSE](LICENSE) file for licensing information.
