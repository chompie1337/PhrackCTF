### Setup Instructions

1. **Build the Challenge Container:**

   ```bash
   docker build -t vnd_server dockerfiles
   ```

2. **Run the Container:**

   ```bash
   docker run -d -p <exposed_challenge_ip>:41414:41414 vnd_server
   ```

3. **Access the Application:**

   ```bash
   nc <exposed_challenge_ip> 41414
   ```
