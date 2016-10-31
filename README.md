# MCM-SDOS
The Secure Delete Object Store - part of the Micro Content Management system (MCM)
![Key Cascade](doc/1.png)

MCM consists of multiple components that form a small experimental content management system.

The Secure Delete Object Store (SDOS) implements a key management mechanism that enables cryptographic deletion of objects. 
SDOS is implemented as an API proxy for the Swift object store from the OpenStack project. SDOS can be used with any unmodified Swift client and server.

### The other parts of the MCM project are
* [-- Deploy Environment (set up everything) --](https://github.com/timwaizenegger/mcm-deployEnvironment)
* [Bluebox web-UI](https://github.com/timwaizenegger/mcm-bluebox)
* [SDOS (Secure Delete Object Store) Cryptographic Deletion](https://github.com/timwaizenegger/mcm-sdos)
* [Metadata Extractor](https://github.com/timwaizenegger/mcm-metadataExtractor)
* [Retention Manager](https://github.com/timwaizenegger/mcm-retentionManager)

## How to use
Always run the `setenv.sh` script first to set the pythonpath and virtual environment. 
Then you can either manually run one of the test/experimental classes:

    . setenv.sh
    
    python mcm/sdos/tester/PerfTest.py
    python mcm/sdos/tester/GeomTest.py
    ...


or start a service that offers the Swift API proxy to which your Swift clients can connect:
    
    . setenv.sh
    python runService_Development.py
    
    
### configuration
is currently done by setting parameters in

     mcm/sdos/configuration.py


## Dev setup
### first setup after new checkout
make sure to specify a python 3 or higher interpreter for your virtualenv (SDOS doesn't support python 2)
in the main directory


    virtualenv venvSDOS
    . setenv.sh
    (included in setenv) source venvSDOS/bin/activate
    pip install -r requirements.txt
    

 
to leave venv

    deactivate
  
    
### use pip to install requirements
just install the existing reqs

    pip install -r requirements.txt
    
install new packages

    pip install <package>


save new packages to requirements:

    pip freeze --local > requirements.txt
    
    
update existing packages

    pip freeze --local | grep -v '^\-e' | cut -d = -f 1 | xargs pip install -U
    pip freeze --local > requirements.txt