# osecm-sdos
The Secure Delete Object Store

## How to use
you can either manually run one of the test/experimental classes:

    tim/sdos/tester/PerfTest.py
    tim/sdos/tester/GeomTest.py


or run it as a service...
    
    coming soon...
    
    
### configuration
is currently done by setting parameters in

     tim/sdos/core/Configuration.py


## Dev setup
### first setup after new checkout
make sure to specify a python 3 or higher interpreter for your virtualenv (SDOS doesn't support python 2)
in the main directory


    virtualenv venvsdos
    . setenv.sh
    (included in setenv) source venvsdos/bin/activate
    pip install -r requirements.txt
    

 
to leave venv

    deactivate
    
    
### running after first setup
in the main directory


    . setenv.sh
    python tim/sdos/tester/PerfTest.py
    (or any other class...)
    
    
### use pip to install requirements
just install the existing reqs

    pip install -r requirements.txt
    
install new packages

    pip install <package>


save new packages to requirements:

    pip freeze --local > requirements.txt