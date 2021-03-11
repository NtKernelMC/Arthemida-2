## Multi Theft Auto: San Andreas

[![Build Status](https://github.com/multitheftauto/mtasa-blue/workflows/Build/badge.svg?event=push&branch=master)](https://github.com/multitheftauto/mtasa-blue/actions?query=branch%3Amaster+event%3Apush) [![Discord](https://img.shields.io/discord/278474088903606273?label=discord&logo=discord)](https://multitheftauto.com/discord) [![Translate](https://img.shields.io/website?down_message=offline&up_message=translate&url=https%3A%2F%2Ftranslate.multitheftauto.com)](https://translate.multitheftauto.com/)

[Multi Theft Auto](https://www.multitheftauto.com/) (MTA) is a software project that adds network play functionality to Rockstar North's Grand Theft Auto game series, in which this functionality is not originally found. It is a unique modification that incorporates an extendable network play element into a proprietary commercial single-player PC game.

## Introduction

Multi Theft Auto is based on code injection and hooking techniques whereby the game is manipulated without altering any original files supplied with the game. The software functions as a game engine that installs itself as an extension of the original game, adding core functionality such as networking and GUI rendering while exposing the original game's engine functionality through a scripting language.

Originally founded back in early 2003 as an experimental piece of C/C++ software, Multi Theft Auto has since grown into an advanced multiplayer platform for gamers and third-party developers. Our software provides a minimal sandbox style gameplay that can be extended through the Lua scripting language in many ways, allowing servers to run custom created game modes with custom content for up to hundreds of online players.

Formerly a closed-source project, we have migrated to open-source to encourage other developers to contribute as well as showing insight into our project's source code and design for educational reasons.

Multi Theft Auto is built upon the "Blue" concept that implements a game engine framework. Since the class design of our game framework is based upon Grand Theft Auto's design, we are able to insert our code into the original game. The game is then heavily extended by providing new game functionality (including tweaks and crash fixes) as well as a completely new graphical interface, networking and scripting component.

## Gameplay content

By default, Multi Theft Auto provides the minimal sandbox style gameplay of Grand Theft Auto. The gameplay can be heavily extended through the use of the Lua scripting language that has been embedded in the client and server software. Both the server hosting the game, as well as the client playing the game are capable of running and synchronizing Lua scripts. These scripts are layered on top of Multi Theft Auto's game framework that consists of many classes and functions so that the game can be adjusted in virtually any possible way.

All gameplay content such as Lua scripts, images, sounds, custom models or textures is grouped into a "resource". This resource is nothing more than an archive (containing the content) and a metadata file describing the content and any extra information (such as dependencies on other resources).

Using a framework based on resources has a number of advantages. It allows content to be easily transferred to clients and servers. Another advantage is that we can provide a way to import and export scripting functionality in a resource. For example, different resources can import (often basic) functionality from one or more common resources. These will then be automatically downloaded and started. Another feature worth mentioning is that server administrators can control the access to specific resources by assigning a number of different user rights to them.

## Development

Our project's code repository can be found on the [multitheftauto/mtasa-blue](https://github.com/multitheftauto/mtasa-blue/) Git repository at [GitHub](https://github.com/). We are always looking for new developers, so if you're interested, here are some useful links:

* [Coding guidelines](https://wiki.mtasa.com/index.php?title=Coding_guidelines)
* [Nightly Builds](https://nightly.mtasa.com/)
* [Wiki Roadmap](https://wiki.mtasa.com/wiki/Roadmap)

### IDE Setup
If not using Visual Studio 2017, download and install the [EditorConfig](https://visualstudiogallery.msdn.microsoft.com/c8bccfe2-650c-4b42-bc5c-845e21f96328) plugin to automatically set up your IDE for the correct formatting.

### Build Instructions
#### Windows

Prerequisites
- [Visual Studio 2019](https://visualstudio.microsoft.com/vs/)
- [Microsoft DirectX SDK](https://www.microsoft.com/en-us/download/details.aspx?id=23549)
- [Git for Windows](https://git-scm.com/download/win) (Optional)

1. Execute `win-create-projects.bat`
2. Open `MTASA.sln` in the `Build` directory
3. Compile
4. Execute: `win-install-data.bat`

#### Linux
Building MTA:SA is only supported on 64-bit Linux OSes. You can however cross-compile a 32-bit version using _gcc-multilib_.
1. Execute `utils/premake5 gmake`
2. `cd Build`
3. Run `make config=release_x86` to build the 32-bit server and `make config=release_x64` to build the 64-bit server (or use `debug` instead of `release` to run an unoptimized debug build)
4. Execute `linux-install-data.sh` (optional step).

#### Linux: Docker Build Environment
If you have problems resolving the required dependencies or want maximum compatibility, you can use our dockerized build environment that ships all needed dependencies. We also use this environment to build the official binaries.

64-bit target:
```
docker run --rm -v `pwd`:/build multitheftauto/mtasa-blue
```

32-bit target:
```
docker run --rm -v `pwd`:/build -e BUILD_BITS=32 multitheftauto/mtasa-blue
```
If the current directory is a valid git repository clone, it will use this as the build source. If not, it will create a (shallow) clone. After compiling, you will find the resulting binaries in `./Bin`.
To build the unoptimised debug build, add `-e BUILD_TARGET=debug` to the docker run arguments.
### Premake FAQ
#### How to add new C++ source files?
Execute `win-create-projects.bat`.

## License

Unless otherwise specified, all source code hosted on this repository is licensed under the GPLv3 license. See the LICENSE file for more details.

Grand Theft Auto and all related trademarks are © Rockstar North 1997–2021.
