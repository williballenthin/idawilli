import envs

### Conda/Mamba
#   Specify the directory under $IDAUSR 
envs.activate_conda_env(env="venv")
#   Prompt for path every startup
# envs.activate_conda_env(env=None)

### VirtualEnv
#   Specify the directory under $IDAUSR 
# envs.activate_virtualenv_env(virtualenv="virtualenv")
#   Prompt for path every startup
# activate_virtualenv_env(virtualenv=None)

### Autodetect + prompt
# envs.detect_env()