# fuzzyHSA

Testing and Fuzzying Framework for HSA and AMD low level software. 

Status report of various issues reported by Tinycorp and status of fixes are tracked [here](https://github.com/nod-ai/fuzzyHSA/wiki/Tinygrad-AMD-Linux-Driver-Crash---Hang-tracker-and-updates) 

Analysis of [Tinygrad KFD and HSA backends](https://gist.github.com/fxkamd/ffd02d66a2863e444ec208ea4f3adc48) 

## Installation

1. pip install .
2. bash autogen_stubs.sh generate=kfd

## Uninstalling

1. bash autogen_stubs.sh clean=kfd
2. pip uninstall fuzzyHSA

## Testing

1. pip install -e '.[testing]'
2. python -m pytest test/

## TODO

* Use kfd_ioctl to create kfd operations in kfd/ops.py.
* Utilize the kfd/ops.py in default fuzz tests. 
* Have ability to pass in user defined config for a dynamic fuzz test.

## Acknowledgments

This project would like to thank the [tinycorp](https://tinygrad.org/), in particular the [tinygrad](https://github.com/tinygrad/tinygrad) framework for their effort pushing the boundaries. Please go give it a try/star!

## License

fuzzyHSA is licensed under the terms of the Apache 2.0 License.
See [LICENSE](LICENSE) for more information.
