# Documentation:
#  - Test Parameters: https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/test-toolkit#test-parameters
#  - Test Cases: https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/test-cases
@{
    Test = @(
        'Parameters Property Must Exist',
        'Parameters Must Be Referenced',
        'Secure String Parameters Cannot Have Default',
        'Resources Should Have Location',
        'VM Size Should Be A Parameter',
        'Min And Max Value Are Numbers',
        'artifacts-parameter',
        'Variables Must Be Referenced',
        'Dynamic Variable References Should Not Use Concat',
        'Providers apiVersions Is Not Permitted',
        'Template Should Not Contain Blanks',
        'DependsOn Must Not Be Conditional',
        'Deployment Resources Must Not Be Debug',
        'adminUsername Should Not Be A Literal',
        'VM Images Should Use Latest Version',
        'Virtual-Machines-Should-Not-Be-Preview',
        'ManagedIdentityExtension must not be used',
        'Outputs Must Not Contain Secrets'
    )
    Skip = @(
        'apiVersions Should Be Recent',
        'IDs Should Be Derived From ResourceIDs',
        'Location Should Not Be Hardcoded',
        'ResourceIds should not contain'
    )
}
