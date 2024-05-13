###############################################################################
# EV script 010 - New EV file using template, add data, create lines
# Example Echoview COM script originally submitted to the Echoview forum by Jeremy Holden
# Downloaded from www.echoview.com
# For assistance, contact Echoview support <support@echoview.com>
###############################################################################

import win32com.client
import os

# Define some variables
template = 'e:/my_template.EV'
workdir = 'e:/test/'

# Write the function
def data_setup (filename):
    '''  (filename) -> str
    Applies a template, creates lines and saves the file as filename.EV

    >>> data_setup('my_filename')
    'my_filename.EV has been created'
    
    '''
    # Open EV connection
    EvApp = win32com.client.Dispatch("EchoviewCom.EvApplication")

    # Create a transect.EV file in workdir
    EvFile = EvApp.NewFile(template)
    
    # Add all dt4 files from within workdir
    ## Specify file extension
    extension = '.dt4'

    ## Get list of files to add
    myfiles = [file for file in os.listdir(workdir) if file.lower().endswith(extension)]
   
    ## Create loop to add all *.dt4 to EV file
    for file in myfiles:
        addfile ="".join([workdir,file])
        EvFile.Filesets.Item(0).Datafiles.Add(addfile)
        
    # Create Lines
    ## Surface
    EvLineSurface = EvFile.Lines.CreateFixedDepth(3.8)
    EvLineSurface.Name = 'SurfaceExclude'
    
    ## 100m line
    EvLine100m = EvFile.Lines.CreateFixedDepth(100)
    EvLine100m.Name = '100m'

    ## Bottom
    EvFile.Properties.LinePick.Algorithm = 2
    EvFile.Properties.LinePick.StartDepth = 5
    EvFile.Properties.LinePick.StopDepth = 200
    EvFile.Properties.LinePick.MinSv = -40
    EvFile.Properties.LinePick.UseBackstep = True
    EvFile.Properties.LinePick.DiscriminationLevel = -50.0
    EvFile.Properties.LinePick.BackstepRange = -0.50
    EvFile.Properties.LinePick.PeakThreshold = -50.0
    EvFile.Properties.LinePick.MaxDropouts = 2
    EvFile.Properties.LinePick.WindowRadius = 8
    EvFile.Properties.LinePick.MinPeakAsymmetry = -1.0
    myvar = EvFile.Variables.FindByName("Fileset1: Sv split beam pings (channel 1)")
    EvLineBottom = EvFile.Lines.CreateLinePick(myvar,True)
    EvLineBottom.Name = 'Bottom'
    
    # Save and close
    myname = "".join([workdir,filename,'.EV'])
    EvFile.SaveAs(myname)
    EvApp.Quit

    return "".join([filename,'.EV has been created'])

# End of Script
