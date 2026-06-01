param(
    [string]$Repo = "ThoisoiThree/fcrypt",
    [string]$Workflow = "npm.yml",
    [string]$Environment = "npm-publish",
    [switch]$SkipLoginCheck
)

$ErrorActionPreference = "Stop"

$packages = @(
    "@thoisoithree/fcrypt",
    "@thoisoithree/fcrypt-linux-x64",
    "@thoisoithree/fcrypt-linux-arm64",
    "@thoisoithree/fcrypt-darwin-x64",
    "@thoisoithree/fcrypt-darwin-arm64",
    "@thoisoithree/fcrypt-win32-x64",
    "@thoisoithree/fcrypt-win32-arm64"
)

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-TrustIds {
    param([object]$Value)

    $ids = New-Object System.Collections.Generic.List[string]

    function Visit {
        param([object]$Node)

        if ($null -eq $Node) {
            return
        }

        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($item in $Node) {
                Visit $item
            }
            return
        }

        if ($Node.PSObject.Properties.Name -contains "id") {
            $id = [string]$Node.id
            if ($id -and -not $ids.Contains($id)) {
                $ids.Add($id)
            }
        }

        foreach ($property in $Node.PSObject.Properties) {
            if ($property.Value -is [System.Management.Automation.PSCustomObject] -or
                ($property.Value -is [System.Collections.IEnumerable] -and $property.Value -isnot [string])) {
                Visit $property.Value
            }
        }
    }

    Visit $Value
    return $ids
}

if (-not (Test-Command "npm")) {
    throw "npm is not installed or is not on PATH. Install Node.js/npm first."
}

$npmVersion = (& npm --version).Trim()
Write-Host "npm version: $npmVersion"

$majorMinor = $npmVersion.Split(".")[0..1] -join "."
if ([version]$majorMinor -lt [version]"11.10") {
    throw "npm trust requires npm >= 11.10.0. Run: npm install -g npm@^11.10.0"
}

if (-not $SkipLoginCheck) {
    Write-Host "Checking npm login..."
    & npm whoami | Out-Host
}

foreach ($package in $packages) {
    Write-Host ""
    Write-Host "=== $package ==="

    Write-Host "Reading existing trusted publishers..."
    $trustJson = ""
    $listExit = 0

    try {
        $trustJson = & npm trust list $package --json 2>$null
        $listExit = $LASTEXITCODE
    } catch {
        $listExit = 1
    }

    if ($listExit -eq 0 -and $trustJson) {
        $trust = $trustJson | ConvertFrom-Json
        $trustIds = Get-TrustIds $trust

        foreach ($trustId in $trustIds) {
            Write-Host "Revoking trust id $trustId..."
            & npm trust revoke $package --id $trustId
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to revoke trust id $trustId for $package"
            }
            Start-Sleep -Seconds 2
        }
    } else {
        Write-Host "No existing trusted publisher found, or npm trust list returned no JSON."
    }

    Write-Host "Creating trusted publisher: repo=$Repo workflow=$Workflow env=$Environment"
    & npm trust github $package --repo $Repo --file $Workflow --env $Environment --allow-publish --yes
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create trusted publisher for $package"
    }

    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "Done. Run the GitHub Actions npm workflow again from branch main."
