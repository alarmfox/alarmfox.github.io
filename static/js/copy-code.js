function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();

    try {
        const copied = document.execCommand("copy");
        textarea.remove();

        return copied
            ? Promise.resolve()
            : Promise.reject(new Error("Copy command failed"));
    } catch (error) {
        textarea.remove();
        return Promise.reject(error);
    }
}

document.querySelectorAll("pre").forEach((codeBlock) => {
    const wrapper = document.createElement("div");
    wrapper.className = "code-block";
    codeBlock.parentNode.insertBefore(wrapper, codeBlock);
    wrapper.appendChild(codeBlock);

    const button = document.createElement("button");
    button.className = "copy-code";
    button.type = "button";
    button.textContent = "copy";
    button.setAttribute("aria-label", "Copy code to clipboard");
    wrapper.appendChild(button);

    let resetTimer;

    button.addEventListener("click", async () => {
        window.clearTimeout(resetTimer);

        try {
            await copyText(codeBlock.textContent);
            button.textContent = "copied!";
            button.classList.remove("copy-failed");
        } catch {
            button.textContent = "copy failed";
            button.classList.add("copy-failed");
        }

        resetTimer = window.setTimeout(() => {
            button.textContent = "copy";
            button.classList.remove("copy-failed");
        }, 2000);
    });
});
