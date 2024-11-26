using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

try {
    # Load configuration from environment variables
    $clientId = $env:Ping_ClientId
    $clientSecret = $env:Ping_ClientSecret
    $scope = $env:Ping_Scope
    $redirectUrl = $env:Ping_RedirectUrl
    $baseUrl = $env:Ping_BaseUrl
    $authorizationPath = $env:Ping_Authorization_Path
    $tokenPath = $env:Ping_Token_Path

    if (-not ($clientId -and $clientSecret -and $scope -and $redirectUrl -and $baseUrl -and $authorizationPath -and $tokenPath)) {
        throw "One or more environment variables are missing. Please verify your app settings."
    }

    # Generate a random state value
    $state = (Get-Random -Minimum 10000 -Maximum 99999).ToString()

    # Construct the authentication URL
    $authenticationUrl = "$baseUrl$authorizationPath?client_id=$clientId&response_type=code&state=$state&scope=$scope&redirect_uri=$redirectUrl"
    Write-Host "Authentication URL: $authenticationUrl"

    # Check if an authorization code is provided in the query string
    $authCode = $Request.Query.auth_code
    if (-not $authCode) {
        # Respond with the authentication URL if no auth code is provided
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body = @{
                message = "Please visit the authentication URL and provide the authorization code."
                auth_url = $authenticationUrl
            } | ConvertTo-Json
        })
        return
    }

    # Step 1: Exchange the authorization code for a token
    $tokenEndpoint = "$baseUrl$tokenPath"
    Write-Host "Exchanging authorization code for token at $tokenEndpoint"
    $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Headers @{
        "Content-Type" = "application/x-www-form-urlencoded"
    } -Body @{
        client_id = $clientId
        client_secret = $clientSecret
        grant_type = "authorization_code"
        code = $authCode
        redirect_uri = $redirectUrl
    } -ErrorAction Stop

    if (-not $tokenResponse.access_token) {
        throw "Failed to retrieve token from PingIdentity. Response: $($tokenResponse | ConvertTo-Json)"
    }
    $pingToken = $tokenResponse.access_token
    Write-Host "PingIdentity token acquired."

    # Step 2: Post the token to App Service login endpoint
    $appServiceLoginEndpoint = "https://funcscustestpscmpazurermon/.auth/login/csping"
    Write-Host "Posting PingIdentity token to App Service login endpoint at $appServiceLoginEndpoint"
    $appServiceResponse = Invoke-RestMethod -Uri $appServiceLoginEndpoint -Method POST -Headers @{
        "Content-Type" = "application/json"
    } -Body (@{ id_token = $pingToken } | ConvertTo-Json) -ErrorAction Stop

    if (-not $appServiceResponse.authenticationToken) {
        throw "Failed to retrieve authentication token from App Service. Response: $($appServiceResponse | ConvertTo-Json)"
    }
    $appServiceToken = $appServiceResponse.authenticationToken
    Write-Host "App Service authentication token acquired."

    # Step 3: Use the token in subsequent requests
    $apiEndpoint = ""
    Write-Host "Sending request to API with X-ZUMO-AUTH header..."
    $apiResponse = Invoke-RestMethod -Uri $apiEndpoint -Method GET -Headers @{
        "X-ZUMO-AUTH" = $appServiceToken
    } -ErrorAction Stop

    # Return the API response
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = $apiResponse | ConvertTo-Json
    })

} catch {
    # Handle any exceptions
    Write-Error "An error occurred: $_"
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::InternalServerError
        Body = @{ error = $_.Exception.Message } | ConvertTo-Json
    })
}
