const express = require("express");
const http = require("http");
const path = require("path");
const helmet = require("helmet");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

/* =========================
   SESSION
========================= */

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "EduNivra-Private-Session-2026",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    maxAge: 30 * 60 * 1000
  }
});

/* =========================
   SOCKET.IO
========================= */

const io = new Server(server, {
  maxHttpBufferSize: 12 * 1024 * 1024
});

/* =========================
   MIDDLEWARE
========================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   USERS
========================= */

const USERS = {
  official: {
    id: "Anish123",
    passwordHash: bcrypt.hashSync("Anish@123", 12),
    name: "Official"
  },

  student: {
    id: "Singhaniya",
    passwordHash: bcrypt.hashSync("Singhaniya@123", 12),
    name: "Student"
  }
};

/* =========================
   MEMORY DATA
========================= */

const onlineUsers = new Map();
const statuses = new Map();

/* =========================
   HELPERS
========================= */

function userById(id) {
  return Object.values(USERS).find(
    user => user.id === id
  );
}

function otherUserId(id) {
  const other = Object.values(USERS).find(
    user => user.id !== id
  );

  return other ? other.id : null;
}

function requireLogin(req, res, next) {
  if (
    !req.session ||
    !req.session.authenticated ||
    !req.session.userId
  ) {
    return res.status(401).json({
      ok: false,
      message: "Login required"
    });
  }

  next();
}

function makeMessageId() {
  return (
    Date.now().toString(36) +
    Math.random().toString(36).slice(2)
  );
}

/* =========================
   LOGIN
========================= */

app.post("/login", async (req, res) => {
  try {
    const username = String(
      req.body.username || ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    const role = String(
      req.body.role || ""
    );

    if (
      role !== "official" &&
      role !== "student"
    ) {
      return res.status(401).json({
        ok: false,
        message: "Invalid login type"
      });
    }

    const user = USERS[role];

    if (!user || user.id !== username) {
      return res.status(401).json({
        ok: false,
        message: "Invalid User ID or Password"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!valid) {
      return res.status(401).json({
        ok: false,
        message: "Invalid User ID or Password"
      });
    }

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({
          ok: false,
          message: "Session error"
        });
      }

      req.session.authenticated = true;
      req.session.userId = user.id;
      req.session.role = role;

      res.json({
        ok: true,
        userId: user.id,
        role,
        name: user.name
      });
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      ok: false,
      message: "Server error"
    });
  }
});

/* =========================
   SESSION
========================= */

app.get("/session", (req, res) => {
  if (
    !req.session ||
    !req.session.authenticated ||
    !req.session.userId
  ) {
    return res.status(401).json({
      ok: false
    });
  }

  const user = userById(
    req.session.userId
  );

  res.json({
    ok: true,
    userId: req.session.userId,
    role: req.session.role,
    name: user ? user.name : ""
  });
});

/* =========================
   LOGOUT
========================= */

app.post("/logout", (req, res) => {
  const userId = req.session
    ? req.session.userId
    : null;

  req.session.destroy(() => {
    if (userId) {
      const socketId =
        onlineUsers.get(userId);

      if (socketId) {
        const socket =
          io.sockets.sockets.get(socketId);

        if (socket) {
          socket.disconnect(true);
        }
      }

      onlineUsers.delete(userId);

      io.emit("user-status", {
        userId,
        online: false
      });
    }

    res.json({
      ok: true
    });
  });
});

/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    app: "EduNivra"
  });
});

/* =========================
   CONTACTS
========================= */

app.get(
  "/contacts",
  requireLogin,
  (req, res) => {
    const myId = req.session.userId;
    const otherId = otherUserId(myId);
    const other = userById(otherId);

    if (!other) {
      return res.json({
        ok: true,
        contacts: []
      });
    }

    res.json({
      ok: true,
      contacts: [
        {
          id: other.id,
          name: other.name,
          online: onlineUsers.has(other.id)
        }
      ]
    });
  }
);

/* =========================
   STATUS
========================= */

app.get(
  "/statuses",
  requireLogin,
  (req, res) => {
    res.json({
      ok: true,
      statuses: Array.from(
        statuses.values()
      )
    });
  }
);

app.post(
  "/status",
  requireLogin,
  (req, res) => {
    const text = String(
      req.body.text || ""
    ).trim();

    if (
      !text ||
      text.length > 500
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Status must be 1-500 characters"
      });
    }

    const user = userById(
      req.session.userId
    );

    const status = {
      id: makeMessageId(),
      userId: req.session.userId,
      name: user ? user.name : "",
      text,
      time: new Date().toISOString()
    };

    statuses.set(
      status.userId,
      status
    );

    io.emit("status-updated");

    res.json({
      ok: true,
      status
    });
  }
);

/* =========================
   SOCKET.IO SESSION
========================= */

io.engine.use(sessionMiddleware);

io.use((socket, next) => {
  const sess =
    socket.request.session;

  if (
    !sess ||
    !sess.authenticated ||
    !sess.userId
  ) {
    return next(
      new Error("Unauthorized")
    );
  }

  const user = userById(
    sess.userId
  );

  if (!user) {
    return next(
      new Error("Unauthorized")
    );
  }

  socket.userId = sess.userId;
  socket.role = sess.role;

  next();
});

/* =========================
   SOCKET CONNECTION
========================= */

io.on("connection", socket => {
  const myId = socket.userId;
  const myUser = userById(myId);

  /*
    Private room for this exact user.
    Only that user's sockets are placed here.
  */
  socket.join(myId);

  /*
    If the same account connects again,
    disconnect its previous socket.
  */
  const oldSocketId =
    onlineUsers.get(myId);

  if (
    oldSocketId &&
    oldSocketId !== socket.id
  ) {
    const oldSocket =
      io.sockets.sockets.get(
        oldSocketId
      );

    if (oldSocket) {
      oldSocket.disconnect(true);
    }
  }

  onlineUsers.set(
    myId,
    socket.id
  );

  io.emit("user-status", {
    userId: myId,
    online: true
  });

  sendContactsState();

  /* =========================
     MESSAGE
  ========================= */

  socket.on(
    "chat-message",
    data => {
      if (
        !data ||
        typeof data !== "object"
      ) {
        return;
      }

      const text =
        typeof data.text === "string"
          ? data.text.trim()
          : "";

      if (
        !text ||
        text.length > 5000
      ) {
        return;
      }

      const recipient =
        otherUserId(myId);

      if (!recipient) {
        return;
      }

      const message = {
        id: makeMessageId(),
        sender: myId,
        senderName:
          myUser ? myUser.name : "",
        recipient,
        type: "text",
        message: text,
        time: new Date().toISOString()
      };

      socket.emit(
        "message-sent",
        {
          ...message,
          status: "sent"
        }
      );

      if (onlineUsers.has(recipient)) {
        io.to(recipient).emit(
          "message-sent",
          {
            ...message,
            status: "delivered"
          }
        );

        socket.emit(
          "message-status",
          {
            messageId: message.id,
            status: "delivered"
          }
        );
      }
    }
  );

  /* =========================
     MEDIA MESSAGE
  ========================= */

  socket.on(
    "media-message",
    data => {
      if (
        !data ||
        typeof data !== "object"
      ) {
        return;
      }

      const type = String(
        data.type || ""
      );

      const allowedTypes = [
        "image",
        "video",
        "audio"
      ];

      if (
        !allowedTypes.includes(type)
      ) {
        return;
      }

      const content =
        typeof data.content === "string"
          ? data.content
          : "";

      if (!content) {
        return;
      }

      if (
        content.length >
        9 * 1024 * 1024
      ) {
        socket.emit(
          "media-error",
          {
            message:
              "File is too large."
          }
        );

        return;
      }

      const allowedPrefixes = {
        image:
          /^data:image\/(jpeg|jpg|png|webp);base64,/i,

        video:
          /^data:video\/(mp4|webm|quicktime);base64,/i,

        audio:
          /^data:audio\/(webm|ogg|mp4|mpeg|wav);base64,/i
      };

      if (
        !allowedPrefixes[type].test(
          content
        )
      ) {
        socket.emit(
          "media-error",
          {
            message:
              "Unsupported media format."
          }
        );

        return;
      }

      const recipient =
        otherUserId(myId);

      if (!recipient) {
        return;
      }

      const message = {
        id: makeMessageId(),
        sender: myId,
        senderName:
          myUser ? myUser.name : "",
        recipient,
        type,
        content,
        time: new Date().toISOString()
      };

      socket.emit(
        "message-sent",
        {
          ...message,
          status: "sent"
        }
      );

      if (onlineUsers.has(recipient)) {
        io.to(recipient).emit(
          "message-sent",
          {
            ...message,
            status: "delivered"
          }
        );

        socket.emit(
          "message-status",
          {
            messageId: message.id,
            status: "delivered"
          }
        );
      }
    }
  );

  /* =========================
     SEEN
  ========================= */

  socket.on(
    "message-seen",
    data => {
      const messageId =
        typeof data === "string"
          ? data
          : data &&
            typeof data.messageId === "string"
            ? data.messageId
            : "";

      if (!messageId) {
        return;
      }

      const recipient =
        otherUserId(myId);

      if (!recipient) {
        return;
      }

      io.to(recipient).emit(
        "message-status",
        {
          messageId,
          status: "seen"
        }
      );
    }
  );

  /* =========================
     TYPING
  ========================= */

  socket.on(
    "typing",
    () => {
      const recipient =
        otherUserId(myId);

      if (!recipient) {
        return;
      }

      io.to(recipient).emit(
        "typing",
        {
          userId: myId,
          name:
            myUser ? myUser.name : ""
        }
      );
    }
  );

  socket.on(
    "stop-typing",
    () => {
      const recipient =
        otherUserId(myId);

      if (!recipient) {
        return;
      }

      io.to(recipient).emit(
        "stop-typing"
      );
    }
  );

  /* =========================
     AUDIO / VIDEO CALL
  ========================= */

  socket.on(
    "call-offer",
    data => {
      const recipient =
        otherUserId(myId);

      if (
        !recipient ||
        !data ||
        !data.offer
      ) {
        return;
      }

      io.to(recipient).emit(
        "call-offer",
        {
          from: myId,
          name:
            myUser ? myUser.name : "",
          offer: data.offer,
          kind:
            data.kind === "video"
              ? "video"
              : "audio"
        }
      );
    }
  );

  socket.on(
    "call-answer",
    data => {
      const recipient =
        otherUserId(myId);

      if (
        !recipient ||
        !data ||
        !data.answer
      ) {
        return;
      }

      io.to(recipient).emit(
        "call-answer",
        {
          from: myId,
          answer: data.answer
        }
      );
    }
  );

  socket.on(
    "ice-candidate",
    data => {
      const recipient =
        otherUserId(myId);

      if (
        !recipient ||
        !data ||
        !data.candidate
      ) {
        return;
      }

      io.to(recipient).emit(
        "ice-candidate",
        {
          from: myId,
          candidate: data.candidate
        }
      );
    }
  );

  socket.on(
    "call-end",
    () => {
      const recipient =
        otherUserId(myId);

      if (recipient) {
        io.to(recipient).emit(
          "call-end"
        );
      }
    }
  );

  /* =========================
     DISCONNECT
  ========================= */

  socket.on(
    "disconnect",
    () => {
      /*
        Only the currently registered socket
        may mark this user offline.
      */
      if (
        onlineUsers.get(myId) ===
        socket.id
      ) {
        onlineUsers.delete(myId);

        io.emit(
          "user-status",
          {
            userId: myId,
            online: false
          }
        );

        sendContactsState();
      }
    }
  );
});

/* =========================
   CONTACT STATE
========================= */

function sendContactsState() {
  for (const [
    userId,
    socketId
  ] of onlineUsers.entries()) {
    const socket =
      io.sockets.sockets.get(socketId);

    if (!socket) {
      continue;
    }

    socket.emit(
      "contacts-state",
      {
        contacts:
          Object.values(USERS)
            .filter(
              user => user.id !== userId
            )
            .map(user => ({
              id: user.id,
              name: user.name,
              online:
                onlineUsers.has(user.id)
            }))
      }
    );
  }
}

/* =========================
   START
========================= */

server.listen(
  3000,
  () => {
    console.log(
      "EduNivra running at http://localhost:3000"
    );
  }
);