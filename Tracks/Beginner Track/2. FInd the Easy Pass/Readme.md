## Challenge Description
Find the password (say PASS) and enter the flag in the form HTB{PASS}

- Download the necessary `find the easy pass` files
That should download the file to your `downloads` directory or wherever you have it set. You need to extract the contents of the `zip` archive but it is password protected. The password is listed on the challenge and it is `hackthebox`. If you’re on Windows you should be able to double click the executable and run it right away. However, if you’re on Linux then you need to run it with emulation software like `wine`.
For the conviniece I ran the file on my Windows machine.

![ep-1](https://user-images.githubusercontent.com/87711310/211159072-6c29d477-f548-4166-b473-ca585cf18611.png)

Now that the application is running it’s a good to make note of the strings you see displayed in the application. This can help track down locations in the program when it’s time to decompile it. The next thing to check is what happens when we submit data to the application.

![ep-2](https://user-images.githubusercontent.com/87711310/211159073-f2d98901-a7a9-4302-8ed9-1a91371abf3c.png)

No matter what we are filling in it will come back with Wrong Password! box. We need to reverse engineer this. Reverse engineering a program just comes down to using the right tools and knowing how to use it. I have search for a program to use for this challenges and came across the Immunity Debugger

Download the [Immunity Debugger](https://debugger.immunityinc.com/ID_register.py) and open it

File -> open and select the easypass.exe file

Debug -> Run

Enter a password and press enter. The only lead we have is the string Wrong Password!

In the debugger in the most right upper box. Right click -> search for -> all referenced text strings

![ep3](https://user-images.githubusercontent.com/87711310/211161700-c96eeb2b-a0ae-4dc1-97fd-a13b23ab6d6f.png)

![ep-4](https://user-images.githubusercontent.com/87711310/211161702-00f7d851-4e93-4650-bf0a-e089602a94e6.png)

Now we have another string to look for or follow. Double click on it and it will bring you back the the first screen but now to the point where the string is found. 

Right above You see the word Call. Right click on it and select Breakpoint – Toggle. This will stop the program at the point of verification

![ep-5](https://user-images.githubusercontent.com/87711310/211161703-d35984f7-aabd-486a-9426-76790a2a982f.png)

Now fill a password again press check password. It will jump out. When it does look at the upp right screen

![ep-6](https://user-images.githubusercontent.com/87711310/211161706-8945dc32-79d7-4270-a437-6ec19a2e8f77.png)

Notice an other word. Try it as a password

![ep-7](https://user-images.githubusercontent.com/87711310/211161769-a4f598c9-dc9e-4def-aa3f-8dc9b81b5a73.png)



Now you can enter the flag and complete challenge.
