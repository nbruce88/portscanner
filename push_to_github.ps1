# PowerShell script to push portscanner project to GitHub
# This script should be run from C:\Users\Nathan\Projects\portscanner

# First, let's make sure we're in the correct directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptPath

Write-Host "Current directory: $(Get-Location)"
Write-Host "Checking if .git exists..."

# Initialize git repository if it doesn't exist
if (!(Test-Path ".git")) {
    Write-Host "Initializing Git repository..."
    git init
} else {
    Write-Host "Git repository already initialized"
}

# Add all files
Write-Host "Adding files..."
git add .

# Commit changes
Write-Host "Committing changes..."
git commit -m "Final project cleanup and documentation updates"

# Set remote URL
Write-Host "Setting remote URL..."
git remote set-url origin https://github.com/nbruce88/portscanner.git

# Push to GitHub
Write-Host "Pushing to GitHub..."
git push -u origin master

Write-Host "Push completed successfully!"