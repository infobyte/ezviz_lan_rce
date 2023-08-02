# builder_image

This docker image builds a compatible gdbserver and the custom binaries used for exploitation and post-exploitation.

To use execute `./build_image_and_run.sh` and within the container copy the resulting binaries to the output directory, which is a volume linked to the current working directory. 