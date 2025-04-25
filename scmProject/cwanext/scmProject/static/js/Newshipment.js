document.addEventListener('DOMContentLoaded', () => {
    const responseMessage = document.getElementById('response-message');

    document.getElementById('shipment-form').addEventListener('submit', function(event) {
        event.preventDefault();

        const formData = {
            shipment_number: parseInt(document.getElementById('sinum').value),
            container_number: parseInt(document.getElementById('cnum').value),
            goods_number: parseInt(document.getElementById('goodsno').value),
            route_details: document.getElementById('rdetails').value,
            goods_type: document.getElementById('gdtypes').value,
            device_id: parseInt(document.getElementById('device').value),
            expected_delivery_date: document.getElementById('exdate').value,
            po_number: parseInt(document.getElementById('ponum').value),
            delivery_number: parseInt(document.getElementById('delnum').value),
            ndc_number: parseInt(document.getElementById('ndcnum').value),
            batch_id: parseInt(document.getElementById('bid').value),
            shipment_description: document.getElementById('sdesc').value
        };

        if (formData.shipment_number.toString().length !== 8) {
            responseMessage.textContent = "Shipment number must be exactly 8 digits.";
            responseMessage.classList.remove("green");
            responseMessage.classList.add("red");
            responseMessage.style.display = "block";
            return;
        }

        responseMessage.style.display = "none";

        const token = localStorage.getItem("access_token");

        fetch("/newshipment", {
            method: "POST",
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        })
        .then(async (response) => {
            if (response.ok) {
                responseMessage.textContent = 'Shipment details submitted successfully!';
                responseMessage.classList.remove("red");
                responseMessage.classList.add("green");
                responseMessage.style.display = "block";
                document.getElementById('shipment-form').reset();
                window.location.href = "/myshipment";
            } else {
                const errorData = await response.json();
                responseMessage.textContent = errorData.detail || "Submission failed. Please try again.";
                responseMessage.classList.remove("green");
                responseMessage.classList.add("red");
                responseMessage.style.display = "block";
            }
        })
        .catch((error) => {
            responseMessage.textContent = "An error occurred while submitting the form. Please try again later.";
            responseMessage.classList.remove("green");
            responseMessage.classList.add("red");
            responseMessage.style.display = "block";
            console.error("Error:", error);
        });
    });

    document.getElementById('canbtn').addEventListener('click', function(event) {
        event.preventDefault();
        document.getElementById('shipment-form').reset();
        responseMessage.style.display = "none";
    });
});

function logout(event) {
    event.preventDefault();

    localStorage.removeItem("access_token");

    fetch("/logout", { 
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json"
        }
    })
    .then(response => {
        if (response.ok) {
            window.location.href = "/login"; 
        } else {
            throw new Error("Logout failed");
        }
    })
    .catch(error => {
        console.error("Logout error:", error);
    });
}

