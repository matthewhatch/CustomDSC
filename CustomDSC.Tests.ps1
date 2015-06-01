Import-Module fmg.powershell.dsc -Force

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Configuration = Get-ServerConfigurationData -ComputerName johndscx04

#This never gets used, it gets passed to a Mock
$secpasswd = ConvertTo-SecureString 'PlainTextPassword' -AsPlainText -Force
$Cred = New-Object -TypeName PSCredential('username',$secpasswd)

Describe 'Get-ServerConfigurationData' {
    Context 'Parameters'{
        $parameters = (Get-Command Get-ServerConfigurationData).Parameters
        
        It 'Should accept computername' {
            $parameters.ContainsKey('ComputerName') | Should Be $true
        }    

        It 'Should accept database' {
            $parameters.ContainsKey('Database') | Should Be $true
        }

        It 'Should accept databaseserver' {
            $parameters.ContainsKey('Database') | Should Be $true
        }

        It 'Should accept Environment' {
            $parameters.ContainsKey('Environment') | Should Be $true
        }
    }

    Context 'Return object'{
        It 'returns an object with a property GUID' {
        (Get-Member -InputObject $Configuration).name -Contains 'GUID' | Should Be $true
        }

        It 'returns an object with a property ComputerName' {
            (Get-Member -InputObject $Configuration).Name -contains 'ComputerName' | Should Be $true
        }

        It 'returns an object with a property Environment'{
            (Get-Member -InputObject $Configuration).Name -contains 'Environment' | Should Be $true
        }

        It 'returns an object with a property URL'{
            (Get-Member -InputObject $Configuration).Name -contains 'URL' | Should Be $true
        }

        It 'returns an object with a property ApplicationEnvironment'{
            (Get-Member -InputObject $Configuration).Name -contains 'ApplicationEnvironment' | Should Be $true
        }

        It 'returns an object with a property CertificateID'{
            (Get-Member -InputObject $Configuration).Name -contains 'CertificateID' | Should Be $true
        }
    }
}

Describe 'New-MetaMOF' {
    
    It 'creates a meta.mof file' {
        $metaMof = $Configuration | New-MetaMOF
        (Join-Path -Path $here -ChildPath 'LCM_Configuration\johndscx04.meta.mof') | Should Exist 
        Remove-MetaMof -ComputerName johndscx04
    }

}

Describe 'Remove-MetaMof' {
    
    It 'removes a meta.mof file' {
        $Configuration | New-MetaMOF
        Remove-MetaMof -ComputerName johndscx04
        (Join-Path -Path $here -ChildPath 'LCM_Configuration\johndscx04') | Should Not Exist
    }
    
}

Describe 'Invoke-DSCBuild' {
    
    Context 'Parameters' {
        $params = (Get-Command Invoke-DSCBuild).Parameters
    
        It 'Accepts ComputerName as a Parameter'{
            $params.ContainsKey('ComputerName') | Should Be $true
        }

        It 'Accepts a string array for ComputerName' {
            $params.ComputerName.ParameterType | Should Be 'String[]'    
        }

        It 'Accepts Credential as a Parameter' {
            $params.ContainsKey('Credential') | Should Be $true
        }

        It 'Accepts a PSCredential for Credential Parameter' {
            $params.Credential.ParameterType | Should Be 'PSCredential'
        }

        It 'Accepts Authentication as a parameter'{
            $params.ContainsKey('Authentication') | Should Be $true
        }
    }

    Context 'Invoke-DSC Build on for 1 Computer'{
        
        Mock -ModuleName fmg.powershell.dsc Set-LCMConfiguration { 
            Write-Output 'Setting LCM Configuration...'
        }
    
        Mock -ModuleName fmg.powershell.dsc Update-LCMConfiguration {
            Write-Output 'Forcing Update...'
        }

        Mock -ModuleName fmg.powershell.dsc Get-OSVersion {
            $properties = @{
                ComputerName = 'johndscx04'
                OSVersion = 'Windows 2008 R2'
            }
            
            Write-Output (New-Object -TypeName PSObject -Property $properties)

        }

        Mock -ModuleName fmg.powershell.dsc Invoke-Command {
            Write-Output 'Invoke-Command has been called!'
        }

        It 'Creates a meta.MOF File' {
            Invoke-DSCBuild -ComputerName 'johndscx04' -Credential $Cred
            (Join-Path -Path $here -ChildPath 'LCM_Configuration\johndscx04.meta.mof') | Should Exist    
        }

        It 'Updates the LocalConfiguration Manager of the remote machine with the DSC Configuration' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc Set-LCMConfiguration -Exactly 1
        }

        It 'Forces the evaluation of the DSC configuration by calling Update-LCMConfiguration'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc Update-LCMConfiguration -Exactly 1
        }

        It 'Checks for OS Version' {
            Invoke-DSCBuild -ComputerName 'johndscx04' -Credential $Cred
            Assert-MockCalled -ModuleName fmg.powershell.dsc Get-OSVersion -Exactly 1 -Scope It    
        }

        It 'Invoke Command is called'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc Invoke-Command -Times 2 -Scope Describe
        }

        Remove-MetaMof -ComputerName 'johndscx04'
   }

   Context 'Invoke-DSCBuIld for an array of Computers' {
        Mock -ModuleName fmg.powershell.dsc Get-OSVersion {
            $properties = @{
                ComputerName = 'johndscx04'
                OSVersion = 'Windows 2008 R2'
            }
            Write-Output (New-Object -TypeName PSObject -Property $properties)

        }

        Mock -ModuleName fmg.powershell.dsc Set-LCMConfiguration { 
            Write-Output 'Setting LCM Configuration...'
        }
    
        Mock -ModuleName fmg.powershell.dsc Update-LCMConfiguration {
            Write-Output 'Forcing Update...'
        }   

        Mock -ModuleName fmg.powershell.dsc Invoke-Command {
            Write-Output 'Invoking Command'
        }

        It 'Creates a meta.MOF File' {
            Invoke-DSCBuild -ComputerName 'johndscx04','johndscx01' -Credential $Cred
            (Join-Path -Path $here -ChildPath 'LCM_Configuration\johndscx04.meta.mof') | Should Exist    
        }

        It 'Calls Set-LCMConfiguration 2 Times' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc Set-LCMConfiguration -Exactly 2
        }

        It 'Calls Update-LCMConfiguration 2 Times'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc Update-LCMConfiguration -Exactly 2
        }
    
        It 'Calls Invoke-Command 2 times'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc Invoke-Command -Times 2 -Scope Describe
        }

        It 'Accepts Pipeline by Property Name for ComputerName' {
            $properties = @{
                ComputerName = 'johndscx04'
            }
            $Computer = New-Object -TypeName PSObject -Property $properties

            $Computer | Invoke-DSCBuild -Credential $Cred
            Assert-MockCalled -ModuleName fmg.powershell.dsc Update-LCMConfiguration -Exactly 1 -Scope It
        }

        It 'throws an error when an invalid value is passed to ComputerName' {
            {Invoke-DSCBuild -ComputerName 'noComp' -Credential $Cred -ErrorAction Ignore} | Should Throw
        }

        Remove-MetaMof -ComputerName 'johndscx04','johndscx01'
   }

   Context 'Get-Help Invoke-DSCBuild' {
        $help = Get-Help Invoke-DSCBuild
        It 'Returns Help' {
            $help | Should Not be $null
        }

        It 'Returns a Synopsis' {
            $help.Synopsis | Should not be $null
        }

        It 'Returns a Description with the correct text' {
            $help.Description.Text | Should be "Invoke-DSCBuild Runs all the commands needed to implement the DSC Configuration. `nRetrieves Configuration datafrom the Configuation Database, Creates Meta.mof file, `nsets the local configuration manager on the target machine, and forces and evaluation on the target machine."
        }

        It 'Returns at least one example' {
            $help.Examples | should not be $null
        }
   }

}

Describe 'Set-LCMConfiguration' {
    
    $params = (Get-Command Set-LCMConfiguration).Parameters
    
    It 'Should accept Parameter Credential' {
        $params.ContainsKey('Credential') | Should Be $true
    }

    It 'Parameter should be a PSCredential' {
        $params.Credential.ParameterType | Should Be 'PSCredential'
    }
}

Describe 'Update-LCMConfiguration' {
    $params = (Get-Command Update-LCMConfiguration).Parameters

    Mock Invoke-Command {
        Write-Output 'Invoke-Command called'
    }

    It 'should contain Credentail Parameter' {
        $params.ContainsKey('Credential') | Should Be $true
    }

    It 'Should be a PSCredential' {
        $Params.Credential.ParameterType | Should Be 'PSCredential'
    }

    It 'Calls Get-Process' {
        #Assert-MockCalled Invoke-Command -Exactly 1
    }

}

Describe 'Get-OSVersion' {
    Mock -ModuleName fmg.powershell.dsc Get-CimInstance {
        $properties = @{
            Version = '6.3.9600'
        }
        Write-Output (New-Object -TypeName PSObject -Property $properties)
    }
    
    $OS = Get-OSVersion -ComputerName 'johndscx04'
    
    It 'returns an object with property OSVersion' {
        $OS.OSVersion | Should Not BeNullOrEmpty
    }
    
    It 'returns an object with property ComputerName' {
        $OS.ComputerName | Should Not BeNullOrEmpty
    }
}

Describe 'Get-KB2883200' {
    Mock -ModuleName fmg.powershell.dsc -CommandName Get-HotFix{
        $properties = @{
            Source = 'server0001'
            Description = 'Update'
            HotFixID = 'KB2883200'
            InstalledBy = 'NT AUTHORITY\SYSTEM'
            InstalledOn = ([System.DateTime]::Now)
        }
        
        Write-Output (New-Object -TypeName PSOBject -Property $properties)        
    }

    It 'should return an abject with property HotFixID'{
        $secpasswd = ConvertTo-SecureString 'PlainTextPassword' -AsPlainText -Force
        $Cred = New-Object -TypeName PSCredential('username',$secpasswd)

        $fix = Get-KB2883200 -ComputerName 'Server001' -Credential $Cred
        $fix.HotFixID | Should Be 'KB2883200'
    }

    It 'Calls Get-HotFix' {
        Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Get-HotFix -Exactly 1
    }
}

Describe 'Get-DSCGuid' {
    
    $parameters = (Get-Command Get-DSCGUID).Parameters

    It 'accepts ConfigurationName as a parameter' {
        $parameters.ContainsKey('ConfigurationName') | Should Be $true
    }

    It 'accepts Version as a parameter' {
        $parameters.ContainsKey('Version') | should Be $true    
    }
}


Describe 'New-MOF'{
    $params = (Get-Command New-MOF).Parameters
    
    It 'Accepts ConfigurationID as a parameter'{
       $params.ContainsKey('ConfigurationID') | Should Be $True
    }

    It 'Accepts ConfigPath as a parameter'{
        $params.ContainsKey('ConfigPath') | Should Be $true
    }

    It 'Accepts OutputPath as a parameter'{
        $params.ContainsKey('OutputPath') | Should Be $true
    }

    It 'returns System.IO.FileInfo'{
        
    }

    It 'Create a new MOF'{
                        
    }

}

Describe 'Get-ConfigurationData' {

    Function Test-ConfigurationData{
    param(
        [string]$Property,

        [string]$Value
    )

        if($PSBoundParameters.ContainsKey('Property') -and $PSBoundParameters.ContainsKey('Value')){
            $param = @{
                $Property = $Value
            }   
            
            $Configuration = Get-ConfigurationData @param
        }
        else{
            $Configuration = Get-ConfigurationData
        }
        
        Context "When passing in $Property" {
            It 'returns an object with property GUID' {
                (Get-Member -InputObject $Configuration[0]).Name -contains 'GUID' | Should Be $true
            }

            It 'returns an object with property ConfigurationName' {
                (Get-Member -InputObject $Configuration[0]).Name -contains 'ConfigurationName' | Should Be $true
            }

            It 'returns an object with property Version' {
                (Get-Member -InputObject $Configuration[0]).Name -contains 'Version' | Should Be $true
            }

            It 'returns an object with property EnvironmentType' {
                (Get-Member -InputObject $Configuration[0]).Name -contains 'EnvironmentType' | Should Be $true
            }

            It 'returns an object with property ComputerName' {
                (Get-Member -InputObject $Configuration[0]).Name -contains 'ComputerName' | Should Be $true
            }

            It 'returns an object with property URL' {
                (Get-Member -InputObject $Configuration[0]).Name -contains 'URL' | Should Be $true
            }

           if(-not([string]::IsNullOrEmpty($property))){
                It "returns only results with $Property that matches $Value" {
                    Foreach($item in $Configuration){
                        $item.$property | Should be $Value                 
                    }
                }
           }
        }
    }
   
    Context 'Parameters'{
        
        $params = (Get-Command Get-ConfigurationData).Parameters
        
        It 'Accepts GUID as a parameter' {
            $params.ContainsKey('GUID') | Should Be $true       
        }

        It 'Accepts Database as a parameter' {
            $params.ContainsKey('Database') | Should Be $true       
        }

        It 'Accepts DatabaseServer as a parameter' {
            $params.ContainsKey('DatabaseServer') | Should Be $true       
        }

        It 'Accepts ConfigurationName as a parameter' {
            $params.ContainsKey('ConfigurationName') | Should Be $true       
        }

        It 'Accepts Version as a parameter' {
            $params.ContainsKey('Version') | Should Be $true
        }

    }

    Test-ConfigurationData -Property 'GUID' -Value '8d7746d9-2770-4352-9e42-dd9df68adc23'
    Test-ConfigurationData -Property 'ConfigurationName' -Value 'BaseAppServer2008R2'
    Test-ConfigurationData -Property 'Version' -Value '1.0'
    Test-ConfigurationData
    
}

Describe 'Invoke-DSCBootstrap' {
   
   Mock -ModuleName fmg.powershell.dsc -CommandName Get-ConfigurationData {
       $properties = @{
            GUID = 'somefakeGUID'
            URL = 'http://some.fake.com'
            Version = '1.0'
            ConfigurationName = 'ConfigName'
            EnvironmentType = 'PRD'
            CertificateID = '49257b33973c7f3dd4285971d149116bc7506822'
            ComputerName = '' #Set this to nothing and then update in the Invoke
       }

       Write-Output (New-Object -TypeName PSObject -Property $properties)

    }

    Mock -ModuleName fmg.powershell.dsc -CommandName New-MetaMOF {
        'New-MetaMof called'
    }

    Mock -ModuleName fmg.powershell.dsc -CommandName Set-LCMConfiguration {
        'Set-LCMConfiguration called'
    }

    Mock -ModuleName fmg.powershell.dsc -CommandName Update-LCMConfiguration {
        'Update-LCMConfiguration'
    }

    Mock -ModuleName fmg.powershell.dsc -CommandName Invoke-DSCBuild {
        'Invoke-DSCBuild called'
    }

   
   Context 'Parameters' {
        $params = (Get-Command Invoke-DSCBootstrap).Parameters
        
        It 'Should accept ComputerName as a parameter'{
            $params.ContainsKey('ComputerName') | Should Be $true
        }

        It 'Should accept ConfigurationName as parameter' {
            $params.ContainsKey('ConfigurationName') | Should Be $true
        }

        It 'Should accept ConfigurationVersion as a parameter' {
            $params.ContainsKey('ConfigurationVersion') | Should Be $true
        }

        It 'Should Accept Credential as a parameter' {
            $params.ContainsKey('Credential') | Should Be $true
        }
   }

   Context 'Calls New-MetaMof, Set-LCMConfiguration, and Update-LCMConfiguration 1 time' {

        Invoke-DSCBootstrap -ComputerName 'Server0001' -Credential $Cred

        It 'Calls Get-ConfigurationData'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Get-ConfigurationData -Exactly 1
        }

        It 'Calls New-MetaMof'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName New-MetaMOF -Exactly 1
        }
    
        It 'Calls Set-LCMConfiguration' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Set-LCMConfiguration -Exactly 1
        }

        It 'Calls Update-LCMConfiguration' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Update-LCMConfiguration -Exactly 1
        }

        It 'Calls Invoke-DSCBuild' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Invoke-DSCBuild -Exactly 1
        }
   }

   Context 'Calls New-MetaMof, Set-LCMConfiguration, and Update-LCMConfiguration 2 times' {
        Invoke-DSCBootstrap -ComputerName 'Server0001','Server00002' -Credential $Cred

        It 'Calls Get-ConfigurationData'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Get-ConfigurationData -Exactly 2
        }

        It 'Calls New-MetaMof'{
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName New-MetaMOF -Exactly 2
        }
    
        It 'Calls Set-LCMConfiguration' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Set-LCMConfiguration -Exactly 2
        }

        It 'Calls Update-LCMConfiguration' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Update-LCMConfiguration -Exactly 2
        }

        It 'Calls Invoke-DSCBuild' {
            Assert-MockCalled -ModuleName fmg.powershell.dsc -CommandName Invoke-DSCBuild -Exactly 2
        }

   }

}