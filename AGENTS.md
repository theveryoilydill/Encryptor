# For agents 

## Theme
Keep it keybase colors, blue accent color, white background color, and black text. Try to keep things minimal and clean.

## Security
This is a high security project where it is critical that everything stays secure. Please make sure that there is no way anything can go wrong. Use these rules to help.

1. Minimize uploads: This will make it easier to see if anything is being exfiltrated. 
2. Keep everything up to date: More on that below

## Always make sure it works
Do as much as you can with the info you are given to make sure that the product looks the best it can, works the best it can, etc. 

## Up to date rule
Make sure that everything in the repo is the latest version. This is to get new features and remove vulerabilities. Here are some examples of things to check for:
* Dependencies in package.json: Use bun update --latest to update.
* NodeJS: Make sure to use the latest
* Github workflows: Use the latest versions for steps like actions/checkout
* Package manager: Use the latest versions of package managers

## Code style
1. No more than 3 levels of recursion
2. Optimize for readability
3. Use DRY: Don't repeat code
4. Direct messages to the user, don't put an explaination for features that I asked you to add, like: Sign in with keybase, but don't store the unencrypted private key in memory. 

## Uploading the finished product (for glm-5.2 in z.ai's website only, if you don't know and are glm-5.2 just assume you are in the website)
1. Make sure to upload in the task output-in the UI it says: "All files in task". Make a zip file with the format of "Iteration_{message_number}", where message number is the current message number starting at 0 (ex if first message sent to you: {Iteration_0}). Inside the zip there is the whole repo. Also upload a git patch file with the same naming scheme that I can git am.
2. Do not put any z.ai branding on the project. Don't put the logo in public/logo.svg.
3. Make sure to always pull for the latest github repo every message.
