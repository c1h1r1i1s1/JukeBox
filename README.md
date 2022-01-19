<div id="top"></div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/c1h1r1i1s1/JukeBox">
    <img src="logo.png" alt="Logo" width="267" height="80">
  </a>

<h3 align="center">JukeBox</h3>

  <p align="center">
    A simple Facebook Messenger bot that adds songs to the que
    <br />
    <a href="https://github.com/c1h1r1i1s1/JukeBox">Github Repo found<strong> Here »</strong></a>
    <br />
    <br />
    <a href="https://github.com/c1h1r1i1s1/JukeBox/issues">Report Bug</a>
    ·
    <a href="https://github.com/c1h1r1i1s1/JukeBox/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>


<!-- ABOUT THE PROJECT -->
## About The Project

<img src="que_added.png" alt="Qued" width="500" height="300" align="center">

Ever been bombarded by song requests when hosting a party? Ever found friends endlessly searching for their private playlists on your phone while you just want to kick back and enjoy the night?
Jukebox takes this modern day issue and applies a modern solution. By connecting to your Facebook Messenger account, the app listens for songs being sent to you, and then simply adds that song to the end of the que on your device.
Hands free, elegant and simple! Enjoy your next parties music curated by the people around you!

<!--Here's a blank template to get started: To avoid retyping too much info. Do a search and replace with your text editor for the following: `c1h1r1i1s1`, `JukeBox`, `twitter_handle`, `linkedin_username`, `email`, `email_client`, `project_title`, `project_description`
-->

<!-- GETTING STARTED -->
## Getting Started

This project has been mainly set up for the Raspberry Pi, however it can be easily run on any system with Python 3. Please note the changes to the server address below if you would like to run the program on a different machine.
To set up this project locally, you will need to create a spotify application that you can authenticate with. 

### Prerequisites

The only package required that does not come with a regular Pi installation is fbchat, a simple python library designed to interact with Facebook Messenger.
* fbchat
  ```sh
  pip3 install fbchat
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/c1h1r1i1s1/JukeBox.git
   ```
2. Install fbchat package
   ```sh
   pip3 install fbchat
   ```
3. Due to issues with song attachments not being read by the fbchat bot, the following changes to the library need to be made to the source files. These are often located in `/usr/local/lib/python3.9/dist-packages/fbchat/` on the Pi:
   * In `fbchat/_state.py`, on line 190, change:    
   `revision = int(r.text.split('"client_revision":', 1)[1].split(",", 1)[0])`   
   to   
   `revision = 1`   
   * In `fbchat/_client.py` on line 772, add the following line:   
   `return j["message_thread"]["messages"]["nodes"]`   
   This will return the entire message early, retaining the extensible attachment before it is cut out.

4. This section describes setting up your spotify app via the spotify developers dashboard.
   * Head over to `https://developer.spotify.com/dashboard/` and log in with your spotify account to create a developer account.
   * Once you have a developer account, create a new app with the 'Create An App' button on the dashboard.
   * After naming the app whatever you like and adding a description, you will be greeted with an overview of your new app.
   * By clicking on `Show Client Secret`, note down your Client ID and Client Secret;. You will need these for authentication.
   * Now click on `Edit Settings` and scroll down to `Redirect URI's`. This is the callback which gives the Pi your authentication details once you hace connected the app to the client Spotify device.
   * <b> For Pi devices: </b> All you need to add in the redirect URI's is `http://raspberrypi.local:8080/`. This is because you can access the Pi via it's hostname on your local network.
   * <b> For others: </b> As you need the program to redirect to your device via the same local address each time, you must have a reserved local IP address set for your device that you can use such as `192.168.0.8`. You would then add `http://192.168.0.8:8080` as the redirect URL. Otherwise, you could have your own hostname being broadcasted across the network such as 'mycomputer' which could then be accessed at `http://mycomputer.local:8080`. Note that in each case, port 8080 must be used.

5. Now that you have your app set up, open `cred.py` in the installation directory. Here you can input your client ID, client Secret, as well as your Facebook login details.
   * <b> NOTE: You must either have 2 Factor Authentication disabled, or be able to receive a login code either via a 2FA code generator or message service. The method of facebook sending a link to allow the connection seems not to work with this version of fbchat.</b>

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

To use the program, simply run
   ```sh
   python3 chat.py
   ```
to start the program.
<p>
After entering your authentication code (If you have 2FA enabled), wait a few seconds and the bot will start listening.

In order to authenticate your Spotify account with the application, open messenger and send the following message to yourself:

`Connect`

The application will then send a link back. Open it. This will ask you to login with your Spotify account and enable the Spotify application you made earlier to read and access the devices you are using and modify the que. After clicking allow, this will redirect you to the Pi with a success message.

Now that your are authenticated, simply go to Spotify and share a song to your messenger profile and watch the song be added to your que!
* Note this is currently turned off for group chats so that songs will only be added from private messages to your Messenger account.
* Further note the authentication via `Connect` only works when YOU send a message to YOURSELF. This is completely possible if you did not know this already.
</p>

<p align="right">(<a href="#top">back to top</a>)</p>


See the [open issues](https://github.com/c1h1r1i1s1/JukeBox/issues) for a full list of proposed features (and known issues).

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue or contact me directly via the details below.
Don't forget to give the project a star! Thanks again!

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<!-- CONTACT -->
## Contact

Christian Fane - lolasocf@gmail.com.com

Project Link: [https://github.com/c1h1r1i1s1/JukeBox](https://github.com/c1h1r1i1s1/JukeBox)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* Thank you to Spotify for their Developer Console services!
* Thank you to [fbchat](https://fbchat.readthedocs.io/en/stable/index.html) for their excellent work!

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[issues-shield]: https://img.shields.io/github/issues/c1h1r1i1s1/JukeBox.svg?style=for-the-badge
[issues-url]: https://github.com/c1h1r1i1s1/JukeBox/issues
[product-screenshot]: images/screenshot.png
