# Define the Add-Numbers function
function Add-Numbers { 
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [int] $Number1,

        [Parameter(Position=1, Mandatory=$true)]
        [int] $Number2
    )

    # Calculate the sum of the two numbers
    $sum = $Number1 + $Number2

    # Return the sum
    return $sum
}

# Define a function to prompt for two numbers and perform addition
function PerformAddition {
    # Prompt the user for the first number
    $num1 = Read-Host -Prompt "Enter the first number"

    # Prompt the user for the second number
    $num2 = Read-Host -Prompt "Enter the second number"

    # Convert input to integers (assuming valid input)
    $num1 = [int]$num1
    $num2 = [int]$num2

    # Call the Add-Numbers function to perform addition
    $result = Add-Numbers -Number1 $num1 -Number2 $num2

    # Display the result
    Write-Host "The sum of $num1 and $num2 is: $result"
}

# Call the PerformAddition function to start the process
PerformAddition
