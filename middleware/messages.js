// A custom middleware to store new messages and retrieve them
// we store the messages on the session so we can access them after a redirect
function messages(req, res, next) {
  // Used to get messages, for examples used in route
  // to then get messages and pass to pug to render
  res.getMessages = () => {
    const messages = req.session.messages;
    // We need to delete the messages after use
    delete req.session.messages;

    return messages;
  };

  // When creating routes we call this as res.addMessage('');
  res.addMessage = (messageText) => {
    // if no array of messages exists create the array :)
    if (!req.session.messages) {
      req.session.messages = [];
    }

    // Now add the message
    req.session.messages.push({ text: messageText });
  };

  next();
}

module.exports = messages;