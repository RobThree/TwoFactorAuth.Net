param($installPath, $toolsPath, $package, $project)

$helpfile = "TwoFactorAuth.Net.Documentation.chm";
$helpfolder = "Documentation"

$project.ProjectItems.Item($helpfolder).ProjectItems.Item($helpfile).Delete();
If ($project.ProjectItems.Item($helpfolder).ProjectItems.Count() -eq 0) {
	$project.ProjectItems.Item($helpfolder).Delete()
}