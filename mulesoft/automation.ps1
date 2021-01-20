    param(
      $user,
      $pass,
      $org_id,
      $env_id,
      $api_version,
      $asset_version,
      $raml_file,
      $api_endpoint,
      $api_proxy,
      $api_name,
      $asset_id,
      $runtime_app_name,
      $application_name,
      $jwtResources,
      $applyJWTPolicy
    )

    $uri = "https://anypoint.mulesoft.com"
    $mulesoft_api_version = "/v1"
    #$gateway_ver = "4.2.2"
    $gateway_ver = "4.3.0"
    $endpointType = $api_endpoint.substring(0,5)
    $tlsContext = "TLSContext"

    ############################################################################

    Write-host "############################# Starting Auto Deployment ############################# `n"

function DeployAPItoExchange{
    param (
        $raml_file,
        $api_name,
		$asset_id,
        $api_version,
        $asset_version,
        $org_id,
        $api_endpoint
    )

    $raml_file_name = (Get-Item $raml_file).name

    ################################
    #Setup the Exchange API payload
    ################################
    $LF = "`r`n"
    $boundary = [guid]::NewGuid().ToString()
    $FileContent = [IO.File]::ReadAllText($raml_file)

    $exchange_body = (
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"organizationId`" $LF",
        $org_id,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"groupId`" $LF",
        $org_id,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"assetId`" $LF",
        $asset_id,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"version`" $LF",
        $asset_version,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"name`" $LF",
        $api_name,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"classifier`" $LF",
        'raml',
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"assetLink`" $LF",
        $api_endpoint,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"apiVersion`" $LF",
        $api_version,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"main`" $LF",
        $raml_file_name,
        "--$($boundary)",
        "Content-Disposition: form-data; name=`"asset`"; filename=`"$raml_file_name`"",
        "Content-Type: application/octet-stream$LF",
        $FileContent,
        "--$($boundary)--$LF"
    ) -join $LF


    ###########################
    #Exchange URL and API call
    ###########################
	Write-host "`n#### Before Exchange URL and API call  ####"
    $url = $uri + "/exchange/api" + $mulesoft_api_version + "/assets"
    Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType "multipart/form-data; boundary=`"$($boundary)`"" -Body $exchange_body
}


##########################
#Get the token
##########################
$headers = @{}

$tokenbody = @{
        username = $user;
        password = $pass;
    } | convertto-json

##################
#Token URL
##################
Write-host "`n############################# Sending request for token #############################"

$url = $uri + "/accounts/login"
$token = Invoke-RestMethod -Method Post -Uri $url -Body $tokenbody -ContentType "application/json"
Write-host "Received Token: $($token.token_type) $($token.access_token)"
$headers.Add("Authorization", "$($token.token_type) $($token.access_token)")



################################################################
#Check to see if API and version already exist in the Exchange
################################################################

Write-host "`n############################# Publishing Asset to Exchange #############################"
$url = $uri + "/exchange/api" + $mulesoft_api_version + "/assets/" + $org_id + "/" + $asset_id

try{
	Write-host "`n#### On current_api ####"
    $current_api = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
}
catch{}

if ( ($current_api) `
        -and ($current_api.assetId.Equals($asset_id)) `
        -and ($current_api.version.Equals($asset_version)) `
        -and ($current_api.versionGroup.Equals($api_version))
    )
        {
           Write-Output "$($api_name) $($api_version) - $($asset_version) already exists in the Exchange"
        }
else{
	Write-host "`n#### Before DeployAPItoExchange  ####"
    DeployAPItoExchange -raml_file $raml_file -api_name $api_name -asset_id $asset_id `
                        -api_version $api_version -asset_version $asset_version `
                        -org_id $org_id -api_endpoint $api_endpoint
    Write-output "Deployed $($api_name) $($api_version)"
    }

########################################
#See if the API is in the environment
########################################

Write-Output "`n############################# Publishing API to API Manager #############################"

$url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis?assetId=" + $asset_id

$deployed_api = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"
$api_id = ""


if ( $deployed_api.total -gt 0 ){
    $api_id = $deployed_api.assets.apis.id
	Write-host "API was already published -- API ID - $($deployed_api.assets.apis.id)"

	Write-host "Verifying if API instance on API Manager has the same Asset version"

	$url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis?assetId=" + $asset_id + "&assetVersion=" + $asset_version

	$deployed_api = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"

	if ( $deployed_api.total -gt 0 ){
		Write-host "API was already published with same asset id -- API ID - $($deployed_api.assets.apis.id)"
	}
    else{
        Write-host "Updating API instance on API Manager to requested Asset version"

        $url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis?assetId=" + $asset_id
        $deployed_api = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"
        Write-host $deployed_api.assets.apis.id

        $url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis/" + "$($deployed_api.assets.apis.id)"
        Write-host $url
        $payload_body = @{
            assetVersion = $asset_version;
        } | convertto-json

        $deployed_api3 = Invoke-RestMethod -Method PATCH -Uri $url -Headers $headers -ContentType "application/json" -Body $payload_body

        Write-host "Updated API instance on API Manager to requested Asset version"
    }

}
else{
		Write-Output "`n### Creating API instance ####`n`n"

		$url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis"
		$body = @{
			endpoint = @{
				type = "raml"
				uri = $api_endpoint
				proxyUri = $api_proxy
				isCloudHub = $True
				referencesUserDomain = $False
				responseTimeout = $Null
				muleVersion4OrAbove = $True
			}
			instanceLabel = $api_name
			spec = @{
				assetId = $asset_id
				version = $asset_version
				groupId = $org_id
			}
		} | ConvertTo-Json
		$deploy_api = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -ContentType "application/json"
		Write-host "Published $($deploy_api.id)"
		$api_id = $deploy_api.id

		$url = $uri + "/secrets-manager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/secretGroups/"
		$secretGroupResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"
		$uuidSecretGroupId = $secretGroupResponse.meta.id

		$url = $uri + "/secrets-manager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/secretGroups/" + $uuidSecretGroupId + "/tlsContexts"
		$tlsContextResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"
		$uuidTlsContextId = $tlsContextResponse.meta.id

		$url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis/" + $api_id

		if ($endpointType -eq "https")
		{
			$body = @{
				endpoint = @{
					tlsContexts = @{
						inbound = @{
							secretGroupId = $uuidSecretGroupId
							tlsContextId = $uuidTlsContextId
							name = $tlsContext
						}
						outbound = @{
							secretGroupId = $uuidSecretGroupId
							tlsContextId = $uuidTlsContextId
							name = $tlsContext
						}
					}
				}
			}  | ConvertTo-Json -Depth 3
		}
		else
		{
			$body = @{
				endpoint = @{
					tlsContexts = @{
						inbound = @{
							secretGroupId = $uuidSecretGroupId
							tlsContextId = $uuidTlsContextId
							name = $tlsContext
						}
					}
				}
			}  | ConvertTo-Json -Depth 3
		}
		$apply_tls_context = Invoke-RestMethod -Method Patch -Uri $url -Headers $headers -Body $body -ContentType "application/json"
}


#####################################
#Deploy Proxy to Runtime Manager
#####################################

Write-Output "`n############################# Deploying Proxy to Runtime Manager #############################"
$url = $uri + "/proxies/xapi" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis/" + $api_id + "/deployments"
$deployed_proxy = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"
$proxy_id = $deployed_proxy.id
$body = @{
	applicationName = $runtime_app_name
	gatewayVersion = $gateway_ver
	overwrite = $True
	type = "CH"
	environmentId = $env_id
	} | ConvertTo-Json

if ($proxy_id) {
	Write-host "Proxy updated"
}
else {
		$deploy_proxy = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -ContentType "application/json"
		Write-host "Proxy Deployed"
	}
###################################################
#Check to see if policy is applied to API
###################################################


if ($applyJWTPolicy -eq "Y") {
	Write-host "`n############################# Applying Policy to API #############################"

	$url = $uri + "/apimanager/api" + $mulesoft_api_version + "/organizations/" + $org_id + "/environments/" + $env_id + "/apis/" + $api_id + "/policies"
	$applied_policies = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ContentType "application/json"

	if ( $applied_policies.policies){
		Write-Output "JWT Validation Policy was already applied to API"
	}
	else {
		$body = @{
			configurationData = @{
				 jwtOrigin = "httpBearerAuthenticationHeader"
				 jwtExpression = "#[attributes.headers['jwt']]"
				 signingMethod = "rsa"
				 signingKeyLength = "256"
				 jwtKeyOrigin = "jwks"
				 textKey = "Text Data"
				 jwksUrl = "https://login.microsoftonline.com/common/discovery/keys"
				 jwksServiceTimeToLive = 60
				 skipClientIdValidation = $True
				 clientIdExpression = "#[vars.claimSet.client_id]"
				 validateAudClaim = $True
				 mandatoryAudClaim = $True
				 supportedAudiences = $jwtResources
				 mandatoryExpClaim = $True
				 mandatoryNbfClaim = $False
				 validateCustomClaim = $False
				 }
			policyTemplateId = "jwt-validation"
			assetId = "jwt-validation"
			assetVersion = "1.1.2"
			groupId = "68ef9520-24e9-4cf2-b2f5-620025690913"
			} | ConvertTo-Json

		$applied_policies = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -ContentType "application/json"
		Write-Output "JWT Validation Policy applied to API"
	}
}

Write-Output "`n############################# Completed Auto Deployment #############################`n`n"
