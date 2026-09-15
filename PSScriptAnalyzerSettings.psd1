<#
    PSScriptAnalyzerSettings.psd1
    ---------------------------------------------------------------------------
    Settings for the powershell-lint job in .github/workflows/validate.yml, and
    for a local run:

        Invoke-ScriptAnalyzer -Path lab/scripts -Recurse `
            -Settings ./PSScriptAnalyzerSettings.psd1 `
            -Severity ParseError, Error, Warning

    The file exists so that a local run and a CI run apply the same rules, the
    same way .yamllint already does for YAML.

    Two decisions are recorded here, both deliberate.

    1. PSAvoidUsingWriteHost is excluded.
       The rule is correct for a module or a function meant to be composed into
       a pipeline: Write-Host writes to the host, not to the output stream, so a
       caller cannot capture it. None of the scripts under lab/scripts/ is that
       kind of code. They are interactive, run once, by hand, in an elevated
       console on the endpoint, and their console output IS the product: a
       coloured step-by-step trace, a prediction table the analyst is meant to
       copy into their notes before opening the SIEM, and a set of
       "what a healthy result looks like" blocks. Rewriting them to
       Write-Output would put that narration into the output stream, where it
       would corrupt the value of any script that returns data, and would strip
       the colour that separates a step header from an ok line from a warning.
       This is a genuine exception, not a silenced warning.

    2. PSUseCompatibleSyntax is enabled and targeted at 5.1.
       The lab endpoint runs Windows PowerShell 5.1. The CI runner does not: the
       job's step runs under pwsh 7, which parses &&, ?? and ternaries happily.
       Without this block the job would silently accept syntax that cannot run
       on the machine these scripts exist for. Measured with PSScriptAnalyzer
       1.25.0: the rule reports at Error severity, so a 5.1-incompatible
       construct fails the build rather than scrolling past in a warning list.
       On the seven scripts under lab/scripts/ it currently reports nothing.
#>

@{
    IncludeDefaultRules = $true

    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
    }
}
