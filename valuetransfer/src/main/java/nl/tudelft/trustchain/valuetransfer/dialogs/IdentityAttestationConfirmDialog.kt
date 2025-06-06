package nl.tudelft.trustchain.valuetransfer.dialogs

import android.annotation.SuppressLint
import android.os.Bundle
import android.text.Html.fromHtml
import android.text.InputType
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.jaredrummler.blockingdialog.BlockingDialogFragment
import com.ncorti.slidetoact.SlideToActView
import nl.tudelft.ipv8.android.IPv8Android
import nl.tudelft.ipv8.attestation.schema.ID_METADATA_RANGE_18PLUS
import nl.tudelft.ipv8.attestation.schema.ID_METADATA_RANGE_UNDERAGE
import nl.tudelft.trustchain.valuetransfer.R
import nl.tudelft.trustchain.valuetransfer.ValueTransferMainActivity
import nl.tudelft.trustchain.valuetransfer.community.IdentityCommunity
import nl.tudelft.trustchain.valuetransfer.databinding.DialogIdentityAttestationConfirmBinding
import nl.tudelft.trustchain.valuetransfer.util.betweenDates
import nl.tudelft.trustchain.valuetransfer.util.getColorIDFromThemeAttribute
import java.lang.IllegalStateException
import java.util.*

@SuppressLint("ValidFragment")
class IdentityAttestationConfirmDialog(
    private val attributeName: String,
    private val idFormat: String,
    private val parentActivity: ValueTransferMainActivity
) : BlockingDialogFragment<String>() {
    @Deprecated("Deprecated in Java")
    override fun onCreateDialog(savedInstanceState: Bundle?): BottomSheetDialog {
        @Suppress("DEPRECATION")
        return activity?.let {
            val bottomSheetDialog = BottomSheetDialog(it, R.style.BaseBottomSheetDialog)
            val binding = DialogIdentityAttestationConfirmBinding.inflate(it.layoutInflater)
            val view = binding.root

            bottomSheetDialog.window!!.navigationBarColor =
                ContextCompat.getColor(
                    parentActivity.applicationContext,
                    getColorIDFromThemeAttribute(parentActivity, R.attr.colorPrimary)
                )

            // Fix keyboard exposing over content of dialog
            bottomSheetDialog.behavior.apply {
                skipCollapsed = true
                state = BottomSheetBehavior.STATE_EXPANDED
            }

            val subtitleView = binding.tvSubTitle
            val attributeValueView = binding.etAttributeValue

            attributeValueView.inputType = InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS

            if (idFormat == ID_METADATA_RANGE_18PLUS || idFormat == ID_METADATA_RANGE_UNDERAGE) {
                val attributeValueAutoGeneratedView = binding.tvAttributeValueAutoGenerated
                val identityCommunity = IPv8Android.getInstance().getOverlay<IdentityCommunity>()!!

                val now = Date()
                val dateOfBirth = identityCommunity.getIdentity()!!.content.dateOfBirth
                val years = betweenDates(dateOfBirth, now).toString()

                attributeValueView.setText(years)
                attributeValueView.isVisible = false
                attributeValueAutoGeneratedView.isVisible = true
                attributeValueAutoGeneratedView.text =
                    resources.getString(R.string.text_attestation_age_automatically_derived, years)
            }

            subtitleView.text =
                fromHtml(
                    resources.getString(
                        R.string.text_attestation_confirm,
                        attributeName,
                        idFormat
                    )
                )

            val confirmSlider = binding.slideConfirmRequestedAttestation
            confirmSlider.isLocked = attributeValueView.text.toString().isEmpty()

            attributeValueView.doAfterTextChanged { state ->
                confirmSlider.isLocked = state == null || state.isEmpty()
            }

            bottomSheetDialog.setContentView(view)
            bottomSheetDialog.show()

            confirmSlider.onSlideCompleteListener =
                object : SlideToActView.OnSlideCompleteListener {
                    override fun onSlideComplete(view: SlideToActView) {
                        attributeValueView.text.toString().let { attributeValue ->
                            setResult(attributeValue, false)
                            bottomSheetDialog.dismiss()
                        }
                    }
                }

            bottomSheetDialog
        }
            ?: throw IllegalStateException(resources.getString(R.string.text_activity_not_null_requirement))
    }
}
