data LocalizedData
{
# culture="en-US"
ConvertFrom-StringData @'
GetServerConfigurationDataError=Failed to retreive data for "{0}".
NewMetaMOFError=Failed to create meta.mof file using "{0}".
CIMSessionError=There was an issue creating CIM session "{0}"
'@
}

function Invoke-DSCBuild{
    <#
        .SYNOPSIS
        Invokes DSC Build process

        .Description
        Invoke-DSCBuild Runs all the commands needed to implement the DSC Configuration. 
        Retrieves Configuration datafrom the Configuation Database, Creates Meta.mof file, 
        sets the local configuration manager on the target machine, and forces and evaluation on the target machine.

        .EXAMPLE
        Invoke-DSCBuild -ComputerName johndscx04

        .EXAMPLE 
        $myCred = Get-Credential
        c:\PS>Invoke-DSCBuild -ComputerName johndscx04 -Credential $MyCred
       

        .PARAMETER ComputerName
        Name of the Targer Node

        .PARAMETER Credential
        PS Credentail needed to set the Local Configuration Manager on the Target Node

        .PARAMETER Authentication
        Authentication type to be used for CIM Session to the remote server
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory=$true)]
        [PSCredential]$Credential = (Get-Credential -Message 'Invoke-DSCBuild: Enter Your Admin Credentials'),

        [ValidateSet('Kerberos','CredSSp','Negotiate')]
        [System.String]
        $Authentication = 'Negotiate'
    )
    
    BEGIN{
         
    }

    Process{
        
        foreach($Computer in $ComputerName){
            
            Write-Verbose "Stopping all WMIPrvSE process on $Computer"
            Invoke-Command -ComputerName $Computer -Credential $Credential -Authentication $Authentication -ScriptBlock {Get-Process WmiPrvSE | Stop-Process -Force}

            Write-Verbose "Checking for OS on $Computer"
            if((Get-OSVersion -ComputerName $Computer -Authentication $Authentication -Credential $Credential).OSVersion -eq 'Windows 2012 R2'){
               
                Write-Verbose "Operating System Requires KB2883200, checking now with username $($Credential.UserName)"
                if(!(Get-KB2883200 -ComputerName $Computer -Credential $Credential)){
                    __throw-error -ErrorId 'Invoke-DSCBuild:OSVersion' -ErrorCategory InvalidOperation -errorMessage 'You are running Windows 2012 R2 without KB2883200'
                }
            }
            
            try{
                Get-ServerConfigurationData -ComputerName $Computer | New-MetaMOF
                
                if($PSCmdlet.ShouldProcess("Setting LCM Configuration on $Computer")){
                    Set-LCMConfiguration -ComputerName $Computer -Authentication $Authentication -Credential $Credential
                }
                
                if($PSCmdlet.ShouldProcess("Updating Local Configuration on $Computer")){
                    Update-LCMConfiguration -ComputerName $Computer -Authentication $Authentication -Credential $Credential
                }
            }
            catch{
                __throw-error -ErrorId 'Invoke-DSCBuild Error' -errorMessage "There was an error Invoking DSC Build. $($Error[0])" -ErrorCategory InvalidData  
            } 
        }
    }
    
    END{}
}

Function New-MOF{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ConfigurationID,

        [ValidateScript({Test-Path $_})]
        [string]$ConfigPath,

        [string]$OutputPath
    )

}

Function Get-KB2883200{
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [PSCredential]$Credential
    )

    Write-Verbose "Checking if KB283200 exists on $ComputerName with $($Credential.UserName)"
    $patch = Get-HotFix -ComputerName $ComputerName -Credential $Credential -Id 'KB2883200' -ErrorAction SilentlyContinue
    if($patch){Write-Verbose $patch}
    Write-Output $patch

}

Function Get-OSVersion {
    <#
        .SYNOPSIS
        Returns the Operating System Version
        
        .DESCRIPTION
        Returns an object that contains the ComputerName and the Name of the Current Operating System
        
        .PARAMETER ComputerName
        Name of the target system    
            
        .EXAMPLE 
        Get-OSVersion -ComputerName 'johndscx04'  
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [PSCredential]$Credential,

        [ValidateSet('Kerberos','CredSSp','Negotiate')]
        [System.String]
        $Authentication = 'Negotiate'
        
    )
    $CIMSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication
    $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CIMSession | Select-Object Version

    Switch($OperatingSystem.Version){
        '6.3.9600' {
            $OsName = 'Windows 2012 R2'
            break
        }
        '6.1.7601' {
            $OsName = 'Windows 2008 R2'
            break
        }
        default{
            $OsName = 'unknown'
            break
        }    
    }

    $properties = @{
        OSVersion = $OsName
        ComputerName = $ComputerName  
    }
    Write-Output (New-Object -TypeName PSObject -Property $properties)

}

function Compare-DSCState{
    <#
        .SYNOPSIS
        Compared Servers configuration GUID with the GUID in the ServerConfiguration Database

        .DESCRIPTION
        Compared Servers configuration GUID with the GUID in the ServerConfiguration Database

        .PARAMETER ComputerName
        Name of the Server to be Validated

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.String[]]$ComputerName
    )
    BEGIN{
        $Cred = Get-Credential -Message 'Enter your Admin Credentials'
    }
    PROCESS{
        foreach($Computer in $ComputerName){
            
            $ConfigurationData = Get-ServerConfigurationData -ComputerName $Computer
            $Block = {
                $LCMGuid = (Get-DscLocalConfigurationManager).ConfigurationID
                $IsDesiredState = Test-DscConfiguration
                
                return @{
                    LCMGuid = $LCMGuid
                    IsDesiredState = $IsDesiredState
                }
            }
            
            [HashTable]$ConfigHash = Invoke-Command -ComputerName $Computer -ScriptBlock $Block -Credential $Cred
            $COnfigHash.Add('ConfigDBGuid',$ConfigurationData.Guid)
            $ConfigHash.Add('ComputerName',$Computer)
           
            $ConfigObject = New-Object -TypeName PSObject -Property $ConfigHash
            
            
            Write-Output $ConfigObject

        }
    }
    END{}
}

function Test-DesiredState{
    <#
        .SYNOPSIS
        Test Servers to see of they are in the desired state
               
        .DESCRIPTION
        Test Servers Desired state calling Test-DSCConfiguration via CIM session

        .PARAMETER ComputerName

        .EXAMPLE
        Test-DesiredState -ComputerName 'johnsomeserverp01'

        .EXAMPLE
        Get-DSCServer | where {$_.ComputerName -match 'css'} | Test-DesiredState
            
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
    )
    BEGIN{
        $cred = Get-Credential -Message 'Enter Your Admin Credentials'
    }
    PROCESS{
        
        foreach($computer in $ComputerName){
            $cimsession = New-CimSession -ComputerName $computer -Credential $cred
            $properties = @{
                ComputerName = $computer
                isDesiredState = Test-DscConfiguration -CimSession $cimsession
            }
            $returnObject = New-Object -TypeName psobject -Property $properties
            Write-Output $returnObject
            
        }
    }
    END{
        Remove-Variable -Name cred 
    }
    
}

function Get-LCMConfiguration{
    <#
        .SYNOPSIS
        Get Local Configuration Manager Configuration from remote machines

        .DESCRIPTION
        Using CIM retreive the LCM Configuration from a remote machine or Many remote machines
        
        .PARAMETER ComputerName
        
        .EXAMPLE
        Get-LCMConfiguration -ComputerName johndscx01 
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
    )
    BEGIN{
        New-Variable -Name cred -Value (Get-Credential)
    }

    PROCESS{
        foreach($computer in $ComputerName){
            try{
                $cimSession = New-CimSession -Credential $cred -ComputerName $computer -ErrorAction Stop
                Get-DscLocalConfigurationManager -CimSession $cimSession
                Remove-CimSession -CimSession $cimSession
            }
            catch{
                Write-Warning "There was an issue connecting to $computer"
            }
        }
    }

    END{
        Remove-Variable -Name cred
    }
}

function Get-DSCServer{
    <#
        .SYNOPSIS
        Retreives all Servers in the Configuration Database
        .Description 
        See Synopsis
        .PARAMETER DatabaseServer
        The Database Server that has the configuration Database. This defaults to JOHNSQLP87
        .PARAMETER Database
        The Name of the Configuration database. This Defaults to PSDSCConfiguration
        .EXAMPLE 
        Get-DSCServer
    #>
    [CmdletBinding()]
    param(
        [string]$Environment,
        [string]$DatabaseServer = 'JOHNSQLP87',
        [string]$Database = 'PSDSCConfiguration'
    )

    BEGIN{
        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        $sqlConnection = __connect-SQL -connectionString $connectionString    
    }
    PROCESS{
        [string]$query = 'SELECT * FROM SERVER'
        if($PSBoundParameters.ContainsKey('Environment')){
            $query += " WHERE EnvironmentID = '$Environment'"
        }
        $data = __get-SQLData -SqlConnection $sqlConnection -Query $query
        
        foreach($item in $data){
            $properties = @{
                ComputerName = $item.Name
                IPAddress = $item.IPAddress
                GUID = $item.ConfigInstanceGUID
                Environment = $item.EnvironmentID
            }
            Write-Output (New-Object -TypeName PSObject -Property $properties)
        }

    }
    END{
        Write-Verbose 'Closing SQL Connection'
        $sqlConnection.Close()    
    }
}
function Get-DSCConfigurationType{
    <#
        .SYNOPSIS
        Return All configurations from the Configuration Database

        .DESCRIPTION
        See SYNOPSIS
        
        .PARAMETER Database
        
        .PARAMETER DatabaseServer

    #>
    [CmdletBinding()]
    param(
        [string]$Database = 'PSDSCConfiguration',
        [string]$DatabaseServer = 'JOHNSQLP87'
    )
    BEGIN{
        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        $sqlConnection = __connect-SQL -connectionString $connectionString
    }
    PROCESS{
        [stirng]$query = 'Select * from Configuration'
        $data = __get-SQLData -SqlConnection $sqlConnection -Query $query
        foreach($item in $data){
            $properties = @{
                Name = $item.Name
                Description = $item.Desc
            }
            $config = New-Object -TypeName PSObject -Property $properties
            Write-Output $config
        }
    }
    END{
        $sqlConnection.Close()
    }
}

function Get-DSCEnvironment{
    <#
        .SYNOPSIS
        Return All environements in the configuration Management Database
        
        .Description
        See Synopsis
        
        .PARAMETER Database

        .PARAMETER DatabaseServer
    #>
    [CmdletBinding()]
    param(
        [string]$Database = 'PSDSCConfiguration',
        [string]$DatabaseServer = 'JOHNSQLP87'
    )

    BEGIN{
        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        $sqlConnection = __connect-SQL -connectionString $connectionString
    }
    PROCESS{
        [string]$query = 'Select * from Environment'
        $data = __get-SQLData -SqlConnection $sqlConnection -Query $query
        foreach($item in $data){
            $properties = @{
                Name = $item.Name
                EnvironmentTypeName = $item.EnvironmentTypeName
            }
        
            $environments = New-Object -TypeName PSObject -Property $properties
            Write-Output $environments
        }
        
    }
    END{
        $sqlConnection.Close()
    }
}

function Get-DSCGuid{
    <#
        .SYNOPSIS
        Return GUIDs from PSDSCConfiguration Database

        .DESCRIPTION
        Return GUIDs from PSDSCConfiguration Database.  
        The object returned will include GUID, Associated Application and Version, 
        and a collection of servers associated with the GUID

        .PARAMETER ConfigurationName
        The Name of the Configuration you want to retrieve the GUIDs for
        
        .PARAMETER DataBaseServer
        ServerName where the Configuration Database lives
        
        .PARAMETER DataBase
        Name of the Server DSC Configuration Database
       
        .EXAMPLE
        Get-DSCGuid
        
        .EXAMPLE
        Get-DSCGuid -ConfigurationName RiskConsole2008R2
        
        .EXAMPLE 
        Get-DSCGUID -DatabaseServer "JOHNSQLD11" -Database "SOMEDSCDatabase" 
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigurationName,

        [string]$Version,

        [string]$DataBaseServer = 'JOHNSQLP87',

        [string]$DataBase = 'PSDSCConfiguration'
    )

    BEGIN{
        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        $sqlConnection = __connect-SQL -connectionString $connectionString    
    }
    PROCESS{
        [string]$ServerQuery = "select c.Guid,c.EnvironmentTypeName,v.Version,conf.Name `
            from ConfigInstance as c `
            JOIN ConfigVersion as v On `
            (c.ConfigVersionID = v.ID) `
            JOIN Configuration as conf On `
        (v.ConfigurationID = conf.Id)"

        if($PSBoundParameters.ContainsKey('ConfigurationName')){
            $ServerQuery += " where conf.Name = '$ConfigurationName'"
        }

        if($PSBoundParameters.ContainsKey('Version')){
            $ServerQuery += " where conf.Name = '$ConfigurationName'"    
        }

        $servers = Get-DSCServer
        $data = __get-SQLData -SqlConnection $sqlConnection -Query $ServerQuery

        foreach($item in $data){
                
            $serverArray = @()
            foreach ($server in ($servers | where-object {$_.Guid -eq $item.guid})){
                $serverArray += $server.ComputerName        
            }

            #Get Servers that match GUID
            $properties = @{
                GUID = $item.Guid
                Servers = $serverArray
                Environment = $Item.EnvironmentTypeName
                Version = $item.Version
                ConfigurationName = $item.Name
            }  
              
            $dataObj = New-Object -TypeName PSObject -Property $properties
            Write-Output $dataObj
        }
    }
    END{
        Write-Verbose 'Closing SQL Connection'
        $sqlConnection.Close()    
    }
    
        
}

function Get-ServerConfigurationData{
    <#
        .SYNOPSIS
        Retreives DSC Configuration Data from Configuration Database

        .DESCRIPTION
        Retrieves DSC Conguration ID, Environment, Certificate Thumbprint, PullServer URL

        .PARAMETER ComputerName
        Array of Computer Names or a single computer name

        .PARAMETER DataBaseServer
        ServerName where the Configuration Database lives

        .PARAMETER DataBase
        Name of the Server DSC Configuration Database

        .Parameter Environment
        Used to Overide the Environment stored in the configuration Management Database

        .EXAMPLE
        Get-ServerConfigurationData -ComputerName johnsvcsd01

        .EXAMPLE
        Get-ServerConfiguration -ComputerName johnsvcsd01 -DatabaseServer johnsqlp87 -Database PSDSCConfiguration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName,

        [string]$DataBaseServer = 'JOHNSQLP87',
        
        [string]$DataBase = 'PSDSCConfiguration',

        [string]$Environment
        
    )
    
    begin{
        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        try{
            $sqlConnection = __connect-SQL -connectionString $connectionString
        }
        catch{
            Throw [System.Exception] $Error[0]
        }
    }

    process{        
        [string]$query = "Select s.Name,s.ConfigInstanceGUID,s.EnvironmentID as ApplicationEnvironment, e.EnvironmentTypeName as Environment `
            from Server as s JOIN Environment as e `
        On (s.EnvironmentID = e.Name) where s.Name = "      
        

        foreach($computer in $ComputerName){
            $ServerQuery = $query + " '$computer'"
            
            try{
                Write-Debug "SQLConnection State: $($sqlConnection.State)"
                $data = __get-SQLData -SqlConnection $sqlConnection -Query $ServerQuery
                
                
                if(-not ($PSBoundParameters.ContainsKey('Environment'))){
                    $Environment = $data.Environment     
                }

                $properties = @{
                    Guid = $data.ConfigInstanceGUID
                    Url = $Environment| __get-pullServerUrl -ErrorAction Stop
                    Environment = $Environment
                    ApplicationEnvironment = $data.ApplicationEnvironment
                    ComputerName = $data.Name
                    CertificateID = '49257b33973c7f3dd4285971d149116bc7506822'
                }

                $ServerConfig = New-Object -TypeName PSObject -Property $properties
                Write-Output $ServerConfig
            }
            catch{
                __throw-error -ErrorId 'Configuration Data' -ErrorCategory InvalidData -errorMessage "There was an issue getting config data. Run Get-DSCServer to check if $DataBase contains $Computer"

            }
        }
    }

    end
    {
        Write-Verbose 'Closing SQL Connection'
        $sqlConnection.Close()
    }
}

function Update-ServerConfiguration{
    <#
        .SYNOPSIS
        Updates a server's GUID in the Configuration Database

        .DESCRIPTION
        Updats the Configuration management Database with the NEw GUID for the  target machine 

        .PARAMETER ComputerName
        Target server

        .PARAMETER GUID
        GUID to assign the target server

        .PARAMETER DatabaseServer
        Name of the server that hosts the configuration database

        .PARAMETER Database
        Name of the configuration Database

        .EXAMPLE 
        Update-ServerConfiguration -ComputerName johndscx04 -GUID '25344dfasdfasdfa34afcdw'
    #>

    #Need to validate that the Configuration the server is being updated to and the environment of the server and GUID match

    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$GUID,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$ApplicationEnvironment,

        [string]$DataBaseServer = 'JOHNSQLP87',
        
        [string]$DataBase = 'PSDSCConfiguration'
    )

    BEGIN{
        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        try{
            $sqlConnection = __connect-SQL -connectionString $connectionString
        }
        catch{
            Throw [System.Exception] $Error[0]
        }   
    }

    PROCESS{
        if($PSBoundParameters.ContainsKey('ApplicaitonEnvironment')){
            [string]$query = "Update Server `
                Set ConfigInstanceGUID = '$GUID',`
                EnvironmentID = '$ApplicationEnvironment'`
            Where Name = '$ComputerName'"
        }
        else{
            [string]$query = "Update Server `
                Set ConfigInstanceGUID = '$GUID'`
            Where Name = '$ComputerName'"
        }
        

        if($PSCmdlet.ShouldProcess("$ComputerName`: Updating to $GUID")){
            Write-Debug "SQLCOnnection Connection String: $($sqlConnection.ConnectionString)"
            Write-Debug "SQLConnection State: $($sqlConnection.State)"
            $rowsAffected = __update-SQLData -SqlConnection $sqlConnection -Query $Query 
            Write-Verbose "Update Complete. row(s) affected: $rowsAffected" 
        }                        
    }

    END{
        Write-Verbose 'Closing SQL Connection'
        $sqlConnection.Close()   
    }

}

function New-MetaMOF{
    <#
        .Synopsis
        Create a DSC Meta MOF - Nodes LCM Configuration
        .DESCRIPTION
        Creates a Meta MOF file for DSC client.  This is used to configure
        the nodes Local Configuration Manager
    
        .PARAMETER ServerConfiguration
        PSObject with Properties ServerName, CertificateID, GUID, URL, Environment
        -ServerName: Name of the Server 
        -CertificateID: The Encrypting/Decrypting Certificate Thumbprint
        -GUID: Configuration ID
        -URL: Pull Server URL
        -Environment: Server Environment

        .PARAMETER ConfigurationMode
        Specifies how the Local Configuration Manager actually applies the configuration to the target nodes

        -ApplyOnly: With this option, DSC applies the configuration and does nothing further unless a new configuration is detected, 
        either by you sending a new configuration directly to the target node (“push”) or if you have configured a “pull” server and DSC discovers a new configuration when it checks with the “pull” server. 
        If the target node’s configuration drifts, no action is taken.

        -ApplyAndMonitor: With this option (which is the default), DSC applies any new configurations, 
        whether sent by you directly to the target node or discovered on a “pull” server. 
        Thereafter, if the configuration of the target node drifts from the configuration file, DSC reports the discrepancy in logs. 
        For more about DSC logging, see Using Event Logs to Diagnose Errors in Desired State Configuration.

        -ApplyAndAutoCorrect: With this option, DSC applies any new configurations, 
        whether sent by you directly to the target node or discovered on a “pull” server. 
        Thereafter, if the configuration of the target node drifts from the configuration file, DSC reports the discrepancy in logs, 
        and then attempts to adjust the target node configuration to bring in compliance with the configuration file.


        .PARAMETER RefreshMode
        Set whether the servers should operate in Push or Pull Mode. This value defaults to Pull.
        
        -Push: In the “push” configuration, you must place a configuration file on each target node, using any client computer.

        -Pull: In the “pull” mode, you must set up a “pull” server for Local Configuration Manager to contact and access the configuration files.
          
    
        .EXAMPLE 
        $ServerConfig = Get-ServerConfigurationData -ComputerName johndscx01
        New-MetaMOF -ServerConfiguration $ServerConfig

        .EXAMPLE
        Get-ServerConfigurationData -ComputerName johndscx01 | New-MetaMOF

        .EXAMPLE
        Get-ServerConfigurationData -ComputerName johndscx01 | New-MetaMOF -RefreshMode Push

        This will create a Meta.mof file for johndscx01 that will use configure the LCM to be on Push Mode

        .EXAMPLE 
        Get-ServerConfigurationData -ComputerName johndscx01 | New-MetaMOF -ConfigurationMode ApplyOnly

        This will create a meta.mof file for johndscx01 that will set the Configuration Mode to ApplyOnly.

        .EXAMPLE 
        Get-ServerConfigurationData -ComputerName johndscx01 | New-MetaMOF -ConfigurationMode ApplyAndMonitor

        This will create a meta.mof file for johndscx01 that will set the Configuration Mode to ApplyAndMonitor

    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param
    (
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true,ParameterSetName='ConfigData')]
        [PSObject]$ServerConfiguration,

        [ValidateSet('ApplyOnly','ApplyAndMonitor','ApplyAndAutoCorrect')]
        [System.String]$ConfigurationMode = 'ApplyAndAutoCorrect',

        [ValidateSet('Pull','Push')]
        [System.String]$RefreshMode = 'Pull'
       
    )

    Begin
    {
        Configuration LCM_Configuration{
            Node $AllNodes.NodeName
            {
                LocalConfigurationManager
                {
                    AllowModuleOverwrite = $true
                    CertificateID = $Node.CertificateID
                    ConfigurationID = $Node.ConfigurationID
                    ConfigurationMode = $Node.ConfigurationMode
                    DownloadManagerCustomData = @{
                        ServerUrl = $Node.DownloadManagerServerURL;
                    AllowUnsecureConnection = 'False' }
                    DownloadManagerName = 'WebDownloadManager'
                    RefreshMode = $Node.RefreshMode
                }
            }
        }

        $mofLocation = Join-Path -Path (Get-Location).path -ChildPath LCM_Configuration 
    }

    Process
    {

        #create the config data hastable
        Write-Verbose "Creating the hashtable for $($ServerConfiguration.ComputerName)"
        $ConfigData = @{
            AllNodes=@(
                @{
                    ConfigurationMode = $ConfigurationMode
                    ConfigurationID = $ServerConfiguration.GUID
                    CertificateID = $ServerConfiguration.CertificateID
                    RefreshMode = $RefreshMode
                    NodeName = $ServerConfiguration.ComputerName
                    DownloadManagerServerURL = $ServerConfiguration.URL
                }
            )
        }

        try{
            if($PSCmdlet.ShouldProcess("create meta.mof from sql data for $($ServerConfiguration.ComputerName)")){
                LCM_Configuration -ConfigurationData $ConfigData
            }
        }
        catch{
            $errorID = 'MOF File creation Error'
            $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidOperation
            $errorMessage = $($LocalizedData.NewMetaMofError) -f ${manifest} ;
            __throw-error -ErrorId $errorID -ErrorCategory $errorCategory -errorMessage $errorMessage
 
        }
    }
    End{}
}

function Set-LCMConfiguration{
    <#
        .Synopsis
        Sets the LCM Configuration on the Server

        .DESCRIPTION
        Updates the servers Local Configuration Manager Configuration 
        based on the meta.mof file in the path.  This will not force the 
        server to evaluate its configuration immediately. By Default a server
        will evaluate it's configuration every 15 minutes. To force an update
        use the command Update-LCMConfiguration
    
        .PARAMETER ComputerName
        Specifies the server you want to Update

        .PARAMETER Path
        Specifies the Path of the meta.mof file you want to push, defaults to .\LCMConfiguration

        .PARAMETER Authentication
        Specifies the type of Authentication, Valid Values Kerberos and CredSsp. The default value is Kerberos

        .EXAMPLE
        Set-LCM -ComputerName johndscx01

        .EXAMPLE 
        Set-LCM -ComputerName johndscx01 -Path .\LCM_Configuration

        .EXAMPLE
        Set-LCM -ComputerName johndscx01 -Path .\LCM_Configuration -Authenticatgion CredSsp
    #>
    [CmdletBinding()]
    Param
    (
        #Computer to Update LCM
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$ComputerName,

        # Path of the machines Meta.mof
        [string]$Path = '.\LCM_Configuration',

        [ValidateSet('Kerberos','CredSSp','Negotiate')]
        [string]$Authentication = 'Negotiate',

        [PSCredential]
        $Credential
    )

    Begin
    {
        
        try
        { 
            If($Authentication -eq "CredSsp"){__enable-CredSSP -ComputerName $ComputerName} 
            $cimSession = New-CimSession -Credential $Credential -ComputerName $ComputerName -Authentication $Authentication
        }
        catch{
            __throw-error -ErrorId 'CIM Connection Error' -ErrorCategory InvalidOperation -errorMessage  $($LocalizedData.CIMSessionError) -f ${ComputerName} 
        }
    }
    Process
    {
        Set-DscLocalConfigurationManager -CimSession $cimSession -Verbose -Path $path
    }
    End
    {
        Remove-CimSession -CimSession $cimSession
    }
}

function Update-LCMConfiguration{
    <#
        .Synopsis
        Forces the LCM to evaluate the server configuration

        .DESCRIPTION
        Forces the Local Configuration to evaluate if it is in 
        Compliance with the configuration it is configured to use

        .EXAMPLE
        Update-LCMConfiguration -ComputerName johndscx03

    #>
    [CmdletBinding()]
    Param
    (
        #Computer Name to force the evaluation
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$ComputerName,

        [ValidateSet('CredSsp','Negotiate','Kerberose')]
        [string]$Authentication = 'Negotiate',

        [String]$Port = '5985',

        [PSCredential]
        $Credential
    )

    Begin{}

    Process
    {

        If($Authentication -eq 'CredSsp'){__enable-CredSSP -ComputerName $ComputerName} 
        $cimSession = New-CimSession -Credential $Credential -ComputerName $ComputerName -Authentication $Authentication -Port $Port 
       
        $params = @{
            CimSession = $cimSession
            Namespace  = 'root/Microsoft/Windows/DesiredStateConfiguration'
            ClassName  = 'MSFT_DSCLocalConfigurationManager'
            MethodName = 'PerformRequiredConfigurationChecks'
            Arguments  = @{
                Flags = [uint32] 1
            }
        }

        try{
            Invoke-CimMethod @params -Verbose
        }
        catch{
            __throw-error -ErrorId 'CIM Connection Error' -ErrorCategory InvalidOperation -errorMessage "There was an issue creating a CIM Session to $ComputerName"
        }
    }

    End{
        Remove-CimSession -CimSession $cimSession
    }
}

Function Remove-MetaMof{
    <#
        .SYNOPSIS 
        Removes the meta.mof file for a server or list of servers
        
        .DESCRIPTION
        Removes the meta.mof file for a server or list of servers from the LCM_Configuration Directory under the current location
        The command is being executed

        .PARAMETER ComputerName
        Name of the Computer you want to remove the assocatied meta.mof file.  This can also be an array of computers

        .EXAMPLE
        Remove-MetaMof -ComputerName johndscx04
        
        .EXAMPLE 
        Remove-MetaMof -ComputerName 'johndscx04','johndscx05'

                
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$ComputerName
    )
    BEGIN{}
    PROCESS{
        Write-Verbose "Starting the removal of Meta mof for $ComputerName"
        foreach($Computer in $ComputerName){
            $Path = ".\LCM_Configuration\$Computer.meta.mof"
            try{
                if($PSCmdlet.ShouldProcess("Removing $Path")){
                    Remove-Item $Path -Force -ErrorAction Stop
                }
            }
            catch{
                __throw-error -ErrorId RemoveMetaMof -ErrorCategory InvalidOperation -errorMessage "There was an issue removing the file $Computer.meta.mof.  It may not exist"
            }
        }
    }
    END{}
}

Function Invoke-DSCBootstrap{
<#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER ComputerName

    .PARAMETER Database

    .PARAMETER DatabaseServer

    .Notes
        This is the FMG Global process for bootstrapping a DSC node, this is used for all server that require IIS. 
        We have run into an issue where any configuration that is loading the Web Server role tries to use another
        resource during the DSC initial run that requires the WebAdministration Module there is a failure.  If we add the roles and
        features 1st and then apply a configuration that includes the roles/features along with the other resources that call
        WebAdministration, then everything works.  So we have a base configuration that needs to be applied 1st, this is being referred to as
        the Bootstrap process... or at least that's how i'm referring to it :).

#>
    [CmdletBinding(SupportsShouldProcess=$true)]
        param(
            #[Parameter(Manadatory=$true)]
            [string[]]
            $ComputerName,

            [string]
            $BaseConfig
        )
}

Function Get-ConfigurationData{
<#
    .SYNOPSIS
        Returns Configuration GUID, ConfigurationName, Version, and EnvironmentType

    .DESCRIPTION
       Returns Configuration GUID, ConfigurationName, Version, and EnvironmentType and can be filtered based 
       on the ConfigurationName or Configuration GUID 

    .PARAMETER ConfigurationName
        Name of the configuration you want to find the associated guid, version, and environment type

    .PARAMETER GUID
        Configuration ID or GUID you want to find the associated name, version, and environment type

    .PARAMETER DatabaseServer
        Name of the database server, this is set by default but can be overridden with this parameter

    .PARAMETER Database
        Name of the database, this is set by default but can be overridden with this parameter

    .EXAMPLE
        Get-DSCConfigurationName
    
    .Notes
        This was built to help us solve the issue we have where we need to run the Invoke-DSCBuild twice, once 
        for the base configuration and the second for the full configuration. The base configuration installs the 
        roles and features which needs to be run before we can use the resources in the 'global lockdown' portion of 
        the configuration.  Now we are going to to use a common base for all like servers, i.e., .NET App Servers will 
        all a common base configuration. So we can automate the initial configuration run based on the server type.
        This function was created to support that effort.        
#>
    [CmdletBinding()]
    param(
        [string]
        $GUID,

        [string]
        $ConfigurationName,

        [string]
        $Version,

        [string]
        $Database = 'PSDSCConfiguration',

        [string]
        $DatabaseServer = 'JOHNSQLP87'
    )

    BEGIN{

        [string]$connectionString = "server=$DataBaseServer;database=$DataBase;trusted_connection=True"
        try{
            $sqlConnection = __connect-SQL -connectionString $connectionString

        }
        catch{
            Throw [System.Exception] $Error[0]
        }
           
    }
    PROCESS{
        [string]$query = 'select c.GUID,cv.Version, con.Name, c.EnvironmentTypeName from ConfigInstance as c JOIN ConfigVersion as cv on (c.ConfigVersionID = cv.id) JOIN Configuration as con on (cv.ConfigurationID = con.id)'

        if($PSBoundParameters.ContainsKey('GUID')){
            if($query -match 'where'){
                $query = "$query and c.GUID = '$GUID'"
            }
            else{
                $query = "$query where c.GUID = '$GUID'"
            }
        }

        if($PSBoundParameters.ContainsKey('ConfigurationName')){
            if($query -match 'where'){
                $query = "$query and con.Name = '$ConfigurationName'"
            }
            else{
                $query = "$query where con.Name = '$ConfigurationName'"
            }
        }

        if($PSBoundParameters.ContainsKey('Version')){
            if($query -match 'where'){
                $query = "$query and cv.Version = '$Version'"
            }
            else{
                $query = "$query where cv.Version = '$Version'"
            }
        }

        $data = __get-SQLData -SqlConnection $sqlConnection -Query $query

        foreach($item in $data){

            $properties = @{
                GUID = $item.GUID
                URL = $item.EnvironmentTypeName | __get-pullServerUrl -ErrorAction Stop
                Version = $item.Version
                ConfigurationName = $item.Name
                EnvironmentType = $item.EnvironmentTypeName
                CertificateID = '49257b33973c7f3dd4285971d149116bc7506822'
                ComputerName = '' #Set this to nothing and then update in the Invoke
            }

            Write-Output (New-Object -TypeName PSObject -Property $properties)
        }
    }
    END{}
}

Function Invoke-DSCBootstrap {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string[]]
        $ComputerName,

        [string]
        $ConfigurationName,

        [string]
        $ConfigurationVersion,

        [PSCredential]
        $Credential
    )

    
    foreach($Computer in $ComputerName){
        $ConfigData = Get-ConfigurationData -ConfigurationName $ConfigurationName -Version $ConfigurationVersion
        $ConfigData.ComputerName = $Computer
        $ConfigData | New-MetaMOF

        if($PSCmdlet.ShouldProcess("Set-LCMConfiguration on $Computer with GUID $($ConfigData.GUID)")){
            Set-LCMConfiguration -ComputerName $Computer -Credential $Credential          
        }
        
        if($PSCmdlet.ShouldProcess("Update-LCMConfiguration on $Computer with GUID $($ConfigData.GUID)")){
            Update-LCMConfiguration -ComputerName $Computer -Credential $Credential
        }

        if($PSCmdlet.ShouldProcess("Invoke-DSCBuild on $Computer with GUID $($ConfigData.GUID)")){
            Invoke-DSCBuild -ComputerName $Computer -Credential $Credential
        }
    }
}

Function __get-pullServerUrl{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Environment
    )

    if($Environment -eq 'PRD' -or $Environment -eq 'PROD'){
        Write-Output 'https://dscpull.corp.fmglobal.com/PSDSCPullServer.svc'
    }
    else{
        Write-Output 'https://dscpull-pp.corp.fmglobal.com/PSDSCPullServer.svc'
    }

}

function __connect-SQL{
    param(
        [string]$connectionString
    )
    try{
            
        Write-Verbose "Setting up SQL Connection using $connectionString"   
        $sqlConnection = New-Object -TypeName System.Data.SqlClient.SqlConnection
        $sqlConnection.ConnectionString = $connectionString
        Write-Verbose "Connected to $Database on $DatabaseServer"

        Write-Output $sqlConnection
    }
    catch{
        Throw [System.Exception] $Error[0]
    }


}

function __update-SQLData{
    param(
        [System.Data.SqlClient.SqlConnection]$SqlConnection,
        [System.String]$Query    
    )

    Write-Verbose "Running query: $Query"
    
    $SqlConnection.open()
    Write-Debug "SQLConnection in Update private function: $($SqlConnection.State)"
    $sqlCommand = New-Object 'System.data.sqlclient.sqlcommand'
    $sqlCommand.Connection = $SqlConnection
            
    #$command = $sqlConnection.CreateCommand()
    $sqlCommand.CommandTimeout = 3000
    $sqlCommand.CommandText = $Query
    
    Write-Verbose 'Query Command Created'

    Write-Verbose 'Updating data'
    Write-Debug "Query: $Query"
    Write-Debug "SQLCommand CommandText: $($sqlCommand.CommandText)"
    $rowsAffected = $sqlCommand.ExecuteNonQuery()
    Write-Output $rowsAffected

}

function __get-SQLData{
    param(
        [System.Data.SqlClient.SqlConnection]$SqlConnection,
        [System.String]$Query
    )
    
    Write-Verbose "Running query: $Query"
            
    $command = $sqlConnection.CreateCommand()
    $command.CommandText = $Query
    Write-Verbose 'Query Command Created'

    Write-Verbose 'Creating Adapter'
    $adapter = New-Object -TypeName System.Data.SqlClient.SqlDataAdapter $command
            
    Write-Verbose 'Creating DataSet'
    $dataset = New-Object -TypeName System.Data.DataSet

    $adapter.Fill($dataset) | Out-Null
    
    Write-Verbose 'Assigning Data set'
       
    Write-Output $dataset.Tables[0]
}

Function __enable-CredSSP{
    param($ComputerName)

    if((Get-Service WINRM).Status -eq 'Stopped'){Start-Service WINRM}
    Enable-WSManCredSSP -Role Client -DelegateComputer $ComputerName -Force | Out-Null

}

function __install-KB2883200{
    param(
        [string]
        $ComputerName,

        [PSCredential]
        $Credential
    )

    $Install = {
        if((Get-HotFix -Id KB2883200 -ErrorAction SilentlyContinue) -ne $null){
            Write-Verbose "Installing KB2883200"
            start-process d:\_patches\KB2883200.msu -ArgumentList '/qb' -Verbose
        }
    }

    New-PSDrive -Name 'X' -PSProvider FileSystem -Root "\\$ComputerName\d$" -Credential $Credential -Verbose | Out-Null
    if(-not(Test-Path -Path X:\_patches)){New-Item -Path X:\_patches -ItemType directory -Verbose | Out-Null}
    
    $Destination = 'x:\_patches\\\johnmgmtp11\softlib\Microsoft\DSC\KB2883200.msu'
    $Source = '\\johnmgmtp11\softlib\Microsoft\DSC\KB2883200.msu'
    
    if(-not(Test-Path -Path $Destination)){Copy-Item -Path $Source -Destination $Destination}
    
    try{
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $Install
    }
    catch{
        __throw-error -ErrorId InstallKB2883200 -ErrorCategory InvalidOperation -errorMessage "There was an issue Installing KB2883200."
    }
    
    
}

function __throw-error{
    param(
        [string]
        $ErrorId,
        
        [System.Management.Automation.ErrorCategory]
        $ErrorCategory,

        [string]
        $errorMessage
    )

    #TODO: Write to the Event Log

    $exception = New-Object System.InvalidOperationException $errorMessage
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $errorId, $errorCategory, $null
    $PSCmdlet.ThrowTerminatingError($errorRecord)   
}

Export-ModuleMember -Function New-MetaMOF
Export-ModuleMember -Function Update-LCMConfiguration
Export-ModuleMember -Function Set-LCMConfiguration
Export-ModuleMember -Function Get-ServerConfigurationData
Export-ModuleMember -Function Get-DscServer
Export-ModuleMember -Function Get-DSCGUID
Export-ModuleMember -Function Get-DSCEnvironment
Export-ModuleMember -Function Get-DSCConfigurationType
Export-ModuleMember -Function Get-LCMConfiguration
Export-ModuleMember -Function Test-DesiredState
Export-ModuleMember -Function Compare-DSCState
Export-ModuleMember -Function Remove-MetaMof
Export-ModuleMember -Function Invoke-DSCBuild
Export-ModuleMember -Function Get-OSVersion
Export-ModuleMember -Function Get-KB2883200
Export-ModuleMember -Function Update-ServerConfiguration
Export-ModuleMember -Function New-MOF
Export-ModuleMember -Function Get-ConfigurationData
Export-ModuleMember -Function Invoke-DSCBootstrap