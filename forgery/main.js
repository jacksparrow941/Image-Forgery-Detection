$(document).ready(function() {
    $('#upload-form').submit(function(event) {
        event.preventDefault();

        var formData = new FormData($('#upload-form')[0]);

        $.ajax({
            url: '/',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.result === 'success') {
                    var canvas = $('#output-canvas')[0];
                    var context = canvas.getContext('2d');
                    var image = new Image();
                    image.onload = function() {
                        canvas.width = image.width;
                        canvas.height = image.height;
                        context.drawImage(image, 0, 0);
                    };
                    image.src = response.data;
                    $('#output-container').show();
                } else {
                    alert('Error processing image');
                }
            }
        });
    });
});
