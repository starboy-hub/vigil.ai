VIGIL fine-tuned classifier
classes: 0=legit, 1=scam, 2=injection
INPUT CONTRACT: pad/truncate to exactly 128 tokens; pass a 4D float32 attention mask of shape [1,1,1,128] with 0.0 at real tokens and -3.4028235e38 at pad positions; NO token_type_ids input — feed only input_ids and attention_mask.

validation report:
              precision    recall  f1-score   support

       legit      0.987     1.000     0.993        76
        scam      1.000     0.992     0.996       127
   injection      1.000     1.000     1.000       170

    accuracy                          0.997       373
   macro avg      0.996     0.997     0.997       373
weighted avg      0.997     0.997     0.997       373
