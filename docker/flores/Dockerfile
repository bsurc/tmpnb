# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
# Derived from scipy-notebook, with minor modification.  Original maintainer is
# the Jupyter Project.
FROM jupyter/scipy-notebook

MAINTAINER Kyle Shannon <kyle@pobox.com>

USER root

# libav-tools for matplotlib anim
RUN apt update && \
    apt install -y --no-install-recommends ffmpeg && \
    apt install -y nano && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

USER $NB_USER

# Install Python 3 packages
# Remove pyqt and qt pulled in for matplotlib since we're only ever going to
# use notebook-friendly backends in these images
# numpy, scikit-learn, pandas, xarray, and bokeh
RUN conda install --quiet --yes \
    'xarray' && \
    conda clean -tipsy
# Activate ipywidgets extension in the environment that runs the notebook server
RUN jupyter nbextension enable --py widgetsnbextension --sys-prefix

# Import matplotlib the first time to build the font cache.
ENV XDG_CACHE_HOME /home/$NB_USER/.cache/
RUN MPLBACKEND=Agg $CONDA_DIR/bin/python -c "import matplotlib.pyplot"

USER $NB_USER
