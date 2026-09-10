document.addEventListener("DOMContentLoaded", () => {

    const encryptFile =
        document.getElementById("encrypt-file");

    const decryptFile =
        document.getElementById("decrypt-file");

    const encryptFileName =
        document.getElementById("encrypt-file-name");

    const decryptFileName =
        document.getElementById("decrypt-file-name");


    if (encryptFile) {

        encryptFile.addEventListener(
            "change",
            () => {

                if (encryptFile.files.length > 0) {

                    encryptFileName.textContent =
                        encryptFile.files[0].name;

                }

            }
        );

    }


    if (decryptFile) {

        decryptFile.addEventListener(
            "change",
            () => {

                if (decryptFile.files.length > 0) {

                    decryptFileName.textContent =
                        decryptFile.files[0].name;

                }

            }
        );

    }


    document
        .querySelectorAll(".show-password")
        .forEach(button => {

            button.addEventListener(
                "click",
                () => {

                    const targetId =
                        button.dataset.target;

                    const input =
                        document.getElementById(
                            targetId
                        );

                    if (input.type === "password") {

                        input.type = "text";

                        button.textContent =
                            "HIDE";

                    } else {

                        input.type = "password";

                        button.textContent =
                            "SHOW";

                    }

                }
            );

        });


    const password =
        document.getElementById(
            "encrypt-password"
        );

    const strength =
        document.getElementById(
            "encrypt-strength"
        );


    if (password && strength) {

        password.addEventListener(
            "input",
            () => {

                const value =
                    password.value;

                let score = 0;

                if (value.length >= 10)
                    score++;

                if (value.length >= 16)
                    score++;

                if (/[A-Z]/.test(value))
                    score++;

                if (/[a-z]/.test(value))
                    score++;

                if (/[0-9]/.test(value))
                    score++;

                if (/[^A-Za-z0-9]/.test(value))
                    score++;


                const percentage =
                    Math.min(
                        100,
                        (score / 6) * 100
                    );

                strength.style.width =
                    percentage + "%";

            }
        );

    }

});