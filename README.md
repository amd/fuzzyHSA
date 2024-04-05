# fuzzyHSA

Testing and Fuzzying Framework for HSA and AMD low level software. 

Status report of various issues reported by Tinycorp and status of fixes are tracked [here](https://github.com/nod-ai/fuzzyHSA/wiki/Tinygrad-AMD-Linux-Driver-Crash---Hang-tracker-and-updates) 

Analysis of [Tinygrad KFD and HSA backends](https://gist.github.com/fxkamd/ffd02d66a2863e444ec208ea4f3adc48) 

## TODO

* Need to create cache directory for generated .hsaco kernels to live, for example `$HOME/.cache/fuzzyHSA`. Then point fuzzyHSA API there

## License

fuzzyHSA is licensed under the terms of the Apache 2.0 License.
See [LICENSE](LICENSE) for more information.
