CamXMCtl
=============

## Description

CamXMCtl is a program to configure cameras that have the embedded components from  
Xiongmaitech.  These components are extremely common in many cameras available 
from chinese suppliers.  The supplied CMS software only runs on windows computers via
IE and this application allows for configuration of a limited number of options via
linux. 

## Running

Compile the application with the usual: 
autoreconf -fiv
./configure
make

Once compiled, run the program using ./camxmctl and then navigate to the webpage of localhost:8765 to 
configure the camera.  Future revisions may include a configuration file that will allow for specification
of a different port and other changes to the options.

## License

CamXMCtl is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) version 3 or later.  A copy of the license
is provided in the doc subdirectory and it can also be obtained from <https://www.gnu.org/licenses/>.


## Contributing

The author is not and has never been a software programmer by profession.  As a result, some of the code may not
conform with ideal coding practices or use the best methods for implementation.  Consider opening issues and 
submitting pull requests to enhance the functionality of the application, correct errors and generally
and contribute positively to the world.

