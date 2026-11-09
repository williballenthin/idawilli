import logging
import envs

#   Comment these lines to revert to logging.WARNING filter
envs.ENV_LOG_LEVEL = logging.INFO
envs.configure_logging()

### Conda/Mamba
#   Specify the directory under $IDAUSR 
# envs.activate_conda_env(env="venv")
#   Prompt for path every startup
# envs.activate_conda_env(env=None)

### VirtualEnv
#   Specify the directory under $IDAUSR 
# envs.activate_virtualenv_env(virtualenv="virtualenv")
#   Prompt for path every startup
# activate_virtualenv_env(virtualenv=None)

### Autodetect or prompt
envs.detect_env(".venv")