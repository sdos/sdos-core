#	Project MCM
#
#	Copyright (C) <2015-2017> Tim Waizenegger, <University of Stuttgart>
#
#	This software may be modified and distributed under the terms
#	of the MIT license.  See the LICENSE file for details.

FROM python:3.6
MAINTAINER Tim Waizenegger <tim.waizenegger@ipvs.uni-stuttgart.de>


#RUN git clone https://github.com/sdos/sdos-core.git
ADD . / sdos-core/
WORKDIR sdos-core
RUN pip install -r requirements-min.txt
RUN cp mcm/sdos/configuration.example.py mcm/sdos/configuration.py

COPY sdos.sh /

EXPOSE 3000

ENTRYPOINT ["/sdos.sh"]
