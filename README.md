# Storyteller Discord RPC

Displays what you're reading or listening to on your Storyteller server as Discord Rich Presence!

## Features
- Shows the current book you are reading or listening to
- Supports both playing and paused states
- Hides books from Discord based on keywords in the title (privacy feature)
- Automatically uploads cover art to Imgur (optional)
- Authenticates with your Storyteller server using username and password
- Works on Windows, Linux, Mac, and Docker

---

![Storyteller Discord Rich Presence Example](docs/static/img/storyteller-discord-rpc-demo.png)

*Replace this image with a screenshot of your Discord Rich Presence showing a Storyteller book, or use a combined Storyteller + Discord logo.*

---

## Configuration

Create a `config.json` file (see `config/config.json.example` for all options):

```json
{
  "discord_client_id": "YOUR_DISCORD_CLIENT_ID",
  "storyteller_url": "http://localhost:3000",
  "storyteller_username": "your_username",
  "storyteller_password": "your_password",
  "show_progress": true,
  "use_storyteller_cover": true,
  "imgur_client_id": "YOUR_IMGUR_CLIENT_ID", // optional
  "exclude_keywords": ["private", "secret"] // books with these words in the title will not be shown
}
```

## Installation & Usage

### Windows
~~- Download and run the installer (admin for autostart)~~ **Not Yet Implimented**
- Build (see below)
- Edit your config file
- The service will ~~run on boot and~~ update your Discord status

### Linux / MacOS
- Build from source
- Edit your config file
- Set up a systemd/user service or launch manually
- Example launchd/user service for macOS is `com.storyteller.discord-rpc.plist`

### Docker **NOT YET IMPLIMENTED*
~~- Clone the repo
- Edit your config file
- Run with `docker compose up -d`~~

## Building from Source

```
git clone https://github.com/erictbar/Storyteller-RPC
cd Storyteller-RPC/storyteller-rpc
cargo build --release
```

## Privacy
- No data is sent anywhere except to Discord and (optionally) Imgur for cover art
- Use `exclude_keywords` to keep certain books private

## Credits
- Based on [audiobookshelf-discord-rpc by 0xGingi](https://github.com/0xGingi/audiobookshelf-discord-rpc)
- Storyteller: https://storyteller-platform.gitlab.io/storyteller/

