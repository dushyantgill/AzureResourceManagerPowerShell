function Get-ARMAccessChangeEvents () {
  PROCESS {
    $output = @()
    #For each subscription that the signed in user has some kind of access in
    $global:ARMSubscriptions.GetEnumerator() | % {
      $startEvents = @{}
      $endEvents = @{}
      $subscription = $_.Value
      #query the Microsoft.Insights Resource Provider - for Events, for the subscription created by the Microsoft.Authorization Rsource Provider
      $base = "/subscriptions/" + $subscription.subscriptionId + "/providers/microsoft.insights/eventtypes/management/values"
      $query = "&`$filter=resourceProvider eq 'Microsoft.Authorization' and "
      $query = $query + "&eventTimestamp le '" + [System.Web.HttpUtility]::UrlEncode([DateTime]::UTCNow.ToString("o")) + "' and ";
      $query = $query + "&eventTimestamp ge '" + [System.Web.HttpUtility]::UrlEncode(([DateTime]::UTCNow - [TimeSpan]::FromDays(30)).ToString("o")) + "'";
      
      $events = Execute-ARMQuery -HTTPVerb GET -SubscriptionId $subscription.subscriptionId -Base $base -Query $query -APIVersion "2014-04-01" -Silent
      
      $events | % {
        if($_.httpRequest -ne $null -and $_.httpRequest.method.ToUpper() -eq "PUT"){
          if($_.status.value -eq "Started"){
            $startEvents.Add($_.operationId, $_) 
          }
          else{
            $endEvents.Add($_.operationId, $_)
          }
        }
      }
      
      $startEvents.GetEnumerator() | % {
        # confirm that the startEvent resulted in an endEvent that succeeded
        if($endEvents[$_.Value.operationId] -ne $null -and $endEvents[$_.Value.operationId].status.value -eq "Succeeded"){
          # instantiate an output event object 
          $out = "" | select Date,DirectoryName,SubscriptionName,SubscriptionId,User,RoleId,RoleName,SubjectId,SubjectType,SubjectName,Scope,ScopeType,ScopeName
          $out.Date = [DateTime]::Parse($_.Value.eventTimestamp)
          $out.DirectoryName = $subscription.tenantName
          $out.SubscriptionName = $subscription.displayName
          $out.SubscriptionId = $subscription.subscriptionId
          #the claims property of events contains the bag of claims from the token of the user that made the change that resulted in the event
          $out.User = $_.Value.claims."http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
          #Microsoft.Authorization events log the request body that contains the information about the role and the subject of the role assignment
          if($_.Value.properties.requestbody -ne $null){
            #get the role id from the request body
            $out.RoleId = (ConvertFrom-Json $_.Value.properties.requestbody).properties.roleDefinitionId
            #convert the role id to role name by querying the Microsoft.Authorization resource provider
            $role = Execute-ARMQuery -HTTPVerb GET -SubscriptionId $subscription.subscriptionId -Base $out.RoleId -APIVersion "2014-07-01-preview" -Silent
            if($role -ne $null){$out.RoleName = $role.properties.roleName}
            #from the request body, get the objectid of the user or group to whom role was assigned
            $out.SubjectId = (ConvertFrom-Json $_.Value.properties.requestbody).properties.principalId
            #covert the object id of the subject to name and type by querying the Azure AD Graph API
            $subject = Get-ARMDirectoryObject -SubscriptionId $subscription.subscriptionId -ObjectId $out.SubjectId -Silent $true
            if($subject -ne $null){
              $out.SubjectType = $subject.objectType
              $out.SubjectName = $subject.displayName
            }
            $out.scope = $_.Value.resourceUri
            #authorization events are created under the URI or the subscription/resource group/resource URI on which access is granted/revoked.
            #get the subscription or the resourcegroup or the resource URI on which access was granted revoked 
            if($out.scope.Contains("/providers/Microsoft.Authorization")){
              $out.scope = $out.Scope.Remove($out.Scope.IndexOf("/providers/Microsoft.Authorization"))
            }
            
            #determine whether the role assignment was added/deleted on subscription or resourcegroup or the resource
            if($out.scope.ToLower().Contains("subscription") -and $out.scope.Split('/').Length -lt 4){
              $out.ScopeType = "Subscription"
              $scope = Execute-ARMQuery -HTTPVerb GET -SubscriptionId $subscription.subscriptionId -Base $out.scope  -APIVersion "2014-04-01-preview" -Silent
              if($scope -ne $null){$out.ScopeName = $scope.displayName + " (Id: " + $scope.subscriptionId + ")"}
            }
            elseif($out.scope.ToLower().Contains("resourcegroups") -and $out.scope.Split('/').Length -lt 6){
              $out.ScopeType = "Resource Group"
              $scope = Execute-ARMQuery -HTTPVerb GET -SubscriptionId $subscription.subscriptionId -Base $out.scope  -APIVersion "2014-04-01-preview" -Silent
              if($scope -ne $null){$out.ScopeName = $scope.name + " (Region: " + $scope.location + ")"}
            }
            elseif($out.scope.ToLower().Contains("providers") -and $out.scope.Split('/').Length -gt 7){
              $out.ScopeType = "Resource"
              $scopeName = $out.scope.Split("/")[$out.scope.Split("/").Length - 1]
              $out.ScopeName = $scopeName + " (Under: " + $out.scope.ToLower().SubString($out.scope.LastIndexOf("providers")).Trim($scopeName.ToLower()).Trim("providers").Trim("/") + ")"
            }
          }
          $output += $out
        }
      }
    }
    $output
  }
}